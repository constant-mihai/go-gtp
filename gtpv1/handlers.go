// Copyright 2019-2024 go-gtp authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package gtpv1

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/wmnsk/go-gtp/gtpv1/ie"
	"github.com/wmnsk/go-gtp/gtpv1/message"
)

// HandlerFunc is a handler for specific GTPv1 message.
type HandlerFunc func(c Conn, senderAddr net.Addr, msg message.Message) error

type msgHandlerMap struct {
	syncMap sync.Map
}

func (m *msgHandlerMap) store(msgType uint8, handler HandlerFunc) {
	m.syncMap.Store(msgType, handler)
}

func (m *msgHandlerMap) load(msgType uint8) (HandlerFunc, bool) {
	handler, ok := m.syncMap.Load(msgType)
	if !ok {
		return nil, false
	}

	return handler.(HandlerFunc), true
}

func newMsgHandlerMap(m map[uint8]HandlerFunc) *msgHandlerMap {
	mhm := &msgHandlerMap{syncMap: sync.Map{}}
	for k, v := range m {
		mhm.store(k, v)
	}

	return mhm
}

func newDefaultMsgHandlerMap() *msgHandlerMap {
	return newMsgHandlerMap(
		map[uint8]HandlerFunc{
			message.MsgTypeTPDU:            handleTPDU,
			message.MsgTypeEchoRequest:     handleEchoRequest,
			message.MsgTypeEchoResponse:    handleEchoResponse,
			message.MsgTypeErrorIndication: handleErrorIndication,
		},
	)
}

func createPacket(
	teid uint32,
	srcIp net.IP, sport uint16, dstIp net.IP, dport uint16,
) (gopacket.SerializeBuffer, error) {
	buffer := gopacket.NewSerializeBuffer()
	gtpLayer := &layers.GTPv1U{
		Version:       1,
		MessageType:   255,
		MessageLength: 20 + 8 + 4, // TODO: Set gopacket option to calculate this
		TEID:          teid,
	}

	innerIPLayer := &layers.IPv4{
		Version:  4,
		IHL:      5,
		Length:   20 + 8 + 4, // TODO: Set gopacket options to calculate this
		Id:       1,
		Flags:    layers.IPv4DontFragment,
		TTL:      128,
		Protocol: layers.IPProtocolUDP,
		// Checksum: TODO: really hope i don't have to set this
		SrcIP: srcIp,
		DstIP: dstIp,
	}

	innerUDPLayer := &layers.UDP{
		SrcPort: layers.UDPPort(sport),
		DstPort: layers.UDPPort(dport),
	}

	innerPayload := gopacket.Payload([]byte("Pong"))

	if err := innerUDPLayer.SetNetworkLayerForChecksum(innerIPLayer); err != nil {
		fmt.Printf("error on SetNetworkLayerForChecksum: %s\n", err.Error())
		return nil, err
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, gtpLayer,
		innerIPLayer, innerUDPLayer, innerPayload,
	)
	if err != nil {
		fmt.Printf("error on SerializeLayers: %s\n", err.Error())
		return nil, err
	}

	return buffer, nil
}

// handleTPDU responds to sender with ErrorIndication by default.
// By disabling it(DisableErrorIndication), it passes unhandled T-PDU to
// user, which can be caught by calling ReadFromGTP.
func handleTPDU(c Conn, senderAddr net.Addr, msg message.Message) error {
	// this should never happen, as the type should have been assured by
	// msgHandlerMap before this function is called.
	pdu, ok := msg.(*message.TPDU)
	if !ok {
		return ErrUnexpectedType
	}
	p := gopacket.NewPacket(pdu.Payload, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})

	innerIP, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		// TODO: metrics
		return fmt.Errorf("error getting inner IP")
	}

	innerUDP, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok {
		// TODO: metrics
		return fmt.Errorf("error getting inner udp")
	}

	// u, ok := c.(*UPlaneConn)
	// if !ok {
	// 	return ErrInvalidConnection
	// }

	// if u.errIndEnabled {
	// 	if err := u.ErrorIndication(senderAddr, pdu); err != nil {
	// 		logf("failed to send Error Indication to %s: %v", senderAddr, err)
	// 	}
	// 	return nil
	// }

	buffer, err := createPacket(
		pdu.TEID(),
		innerIP.DstIP, uint16(innerUDP.DstPort),
		innerIP.SrcIP, uint16(innerUDP.SrcPort),
	)
	if err != nil {
		return err
	}

	senderAddrSplit := strings.Split(senderAddr.String(), ":")
	sgwAddr, err := net.ResolveUDPAddr(senderAddr.Network(), senderAddrSplit[0]+":2152")
	if err != nil {
		return err
	}

	// NOTE: This write doesn't have a deadline.
	// Very high rates of incoming traffic will make this block for a long time.
	// This function is run in a goroutine. For every incoming message a new goroutine gets spawned.
	// For every message we have to send out we create a new gopacket buffer.
	// If these goroutines never finish the garbage collector never cleans up the buffers.
	// Eventually the whole system freezes and a reboot is necessary.
	if _, err := c.WriteTo(buffer.Bytes(), sgwAddr); err != nil {
		// TODO: metrics
		// fmt.Printf("Error %s writing to %v:\n", err.Error(), senderAddr)
	}

	// tpdu := &tpduSet{
	// 	raddr:   senderAddr,
	// 	teid:    pdu.TEID(),
	// 	seq:     pdu.Sequence(),
	// 	payload: pdu.Payload,
	// }

	// wait for the T-PDU passed to u.tpduCh to be read by ReadFromGTP.
	// if it got stuck for 3 seconds, it discards the T-PDU received.
	// go func() {
	// 	select {
	// 	case u.tpduCh <- tpdu:
	// 		return
	// 	case <-time.After(3 * time.Second):
	// 		return
	// 	}
	// }()

	return nil
}

func handleEchoRequest(c Conn, senderAddr net.Addr, msg message.Message) error {
	// this should never happen, as the type should have been assured by
	// msgHandlerMap before this function is called.
	if _, ok := msg.(*message.EchoRequest); !ok {
		return ErrUnexpectedType
	}

	// respond with EchoResponse.
	return c.RespondTo(
		senderAddr, msg, message.NewEchoResponse(0, ie.NewRecovery(c.Restarts())),
	)
}

func handleEchoResponse(c Conn, senderAddr net.Addr, msg message.Message) error {
	// this should never happen, as the type should have been assured by
	// msgHandlerMap before this function is called.
	if _, ok := msg.(*message.EchoResponse); !ok {
		return ErrUnexpectedType
	}

	// do nothing.
	return nil
}

func handleErrorIndication(c Conn, senderAddr net.Addr, msg message.Message) error {
	// this should never happen, as the type should have been assured by
	// msgHandlerMap before this function is called.
	ind, ok := msg.(*message.ErrorIndication)
	if !ok {
		return ErrUnexpectedType
	}

	// just log and return
	logf("Ignored Error Indication: %v", &ErrorIndicatedError{
		TEID: ind.TEIDDataI.MustTEID(),
		Peer: ind.GTPUPeerAddress.MustIPAddress(),
	})
	return nil
}
