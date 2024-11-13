// Copyright 2019-2024 go-gtp authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/wmnsk/go-gtp"
	"github.com/wmnsk/go-gtp/gtpv1"
	g1message "github.com/wmnsk/go-gtp/gtpv1/message"
	"github.com/wmnsk/go-gtp/gtpv2"
	"github.com/wmnsk/go-gtp/gtpv2/ie"
	g2message "github.com/wmnsk/go-gtp/gtpv2/message"
)

var subIPMap map[string]string = map[string]string{}
var genIP net.IP

func getNextIP() net.IP {
	for i := len(genIP) - 1; i >= 0; i-- {
		genIP[i]++
		if genIP[i] != 0 {
			break
		}
	}

	return genIP
}

func populateSubscribers(startImsi int) {

	genIP = net.ParseIP("10.10.10.1")
	for i := 0; i < 100000; i++ {
		imsi := fmt.Sprintf("%015s", strconv.FormatUint(uint64(startImsi+i), 10))
		subIPMap[imsi] = getNextIP().String()
	}
}

// getSubscriberIP is to get IP address to be assigned to the subscriber.
//
// In the real case, P-GW may ask AAA and PCRF retrieve required information for subscriber,
// but here, to keep the example simple, this just returns subscriber's IP address defined in
// the map "subIPMap".
func getSubscriberIP(sub *gtpv2.Subscriber) (string, error) {
	if ip, ok := subIPMap[sub.IMSI]; ok {
		return ip, nil
	}
	return "", fmt.Errorf("subscriber %s not found", sub.IMSI)
}

var (
	loggerCh = make(chan string)
	errCh    = make(chan error)

	uConn *gtpv1.UPlaneConn
)

func handleCreatePdpContextRequest(c *gtpv2.Conn, sgwAddr net.Addr, msg gtp.Message) error {
	if msg.Version() != 1 {
		return fmt.Errorf("wrong version")
	}

	createPdpReq := msg.(*g1message.CreatePDPContextRequest)
	fmt.Printf("create PDP req: %v\n", createPdpReq)
	return nil
}

func handleDeletePdpContextRequest(c *gtpv2.Conn, sgwAddr net.Addr, msg gtp.Message) error {
	if msg.Version() != 1 {
		return fmt.Errorf("wrong version")
	}
	deletePdpReq := msg.(*g1message.DeletePDPContextRequest)
	fmt.Printf("create PDP req: %v\n", deletePdpReq)
	return nil
}

func handleCreateSessionRequest(c *gtpv2.Conn, sgwAddr net.Addr, genericMsg gtp.Message) error {
	if genericMsg.Version() != 2 {
		return fmt.Errorf("wrong version")
	}
	msg, ok := genericMsg.(g2message.Message)
	if !ok {
		return fmt.Errorf("could not cast message")
	}
	loggerCh <- fmt.Sprintf("Received %s from %s", msg.MessageTypeName(), sgwAddr)

	// assert type to refer to the struct field specific to the message.
	// in general, no need to check if it can be type-asserted, as long as the MessageType is
	// specified correctly in AddHandler().
	csReqFromSGW := msg.(*g2message.CreateSessionRequest)

	// keep session information retrieved from the message.
	session := gtpv2.NewSession(sgwAddr, &gtpv2.Subscriber{Location: &gtpv2.Location{}})
	bearer := session.GetDefaultBearer()
	var err error
	if imsiIE := csReqFromSGW.IMSI; imsiIE != nil {
		imsi, err := imsiIE.IMSI()
		if err != nil {
			return err
		}
		session.IMSI = imsi

		// remove previous session for the same subscriber if exists.
		sess, err := c.GetSessionByIMSI(imsi)
		if err != nil {
			switch err.(type) {
			case *gtpv2.UnknownIMSIError:
				// whole new session. just ignore.
			default:
				return fmt.Errorf("got something unexpected: %w", err)
			}
		} else {
			c.RemoveSession(sess)
		}
	} else {
		return &gtpv2.RequiredIEMissingError{Type: ie.IMSI}
	}
	//if msisdnIE := csReqFromSGW.MSISDN; msisdnIE != nil {
	//session.MSISDN, err = msisdnIE.MSISDN()
	//if err != nil {
	//return err
	//}
	//} else {
	//return &gtpv2.RequiredIEMissingError{Type: ie.MSISDN}
	//}
	//if meiIE := csReqFromSGW.MEI; meiIE != nil {
	//session.IMEI, err = meiIE.MobileEquipmentIdentity()
	//if err != nil {
	//return err
	//}
	//} else {
	//return &gtpv2.RequiredIEMissingError{Type: ie.MobileEquipmentIdentity}
	//}
	if apnIE := csReqFromSGW.APN; apnIE != nil {
		bearer.APN, err = apnIE.AccessPointName()
		if err != nil {
			return err
		}
	} else {
		return &gtpv2.RequiredIEMissingError{Type: ie.AccessPointName}
	}
	if netIE := csReqFromSGW.ServingNetwork; netIE != nil {
		session.MNC, err = netIE.MNC()
		if err != nil {
			return err
		}
	} else {
		return &gtpv2.RequiredIEMissingError{Type: ie.ServingNetwork}
	}
	if ratIE := csReqFromSGW.RATType; ratIE != nil {
		session.RATType, err = ratIE.RATType()
		if err != nil {
			return err
		}
	} else {
		return &gtpv2.RequiredIEMissingError{Type: ie.RATType}
	}
	if fteidcIE := csReqFromSGW.SenderFTEIDC; fteidcIE != nil {
		teid, err := fteidcIE.TEID()
		if err != nil {
			return err
		}
		session.AddTEID(gtpv2.IFTypeS5S8SGWGTPC, teid)
	} else {
		return &gtpv2.RequiredIEMissingError{Type: ie.FullyQualifiedTEID}
	}

	var teidOut uint32
	if brCtxIE := csReqFromSGW.BearerContextsToBeCreated; brCtxIE != nil {
		for _, childIE := range brCtxIE[0].ChildIEs {
			switch childIE.Type {
			case ie.EPSBearerID:
				bearer.EBI, err = childIE.EPSBearerID()
				if err != nil {
					return err
				}
			case ie.FullyQualifiedTEID:
				it, err := childIE.InterfaceType()
				if err != nil {
					return err
				}
				teidOut, err := childIE.TEID()
				if err != nil {
					return err
				}
				session.AddTEID(it, teidOut)
			}
		}
	} else {
		return &gtpv2.RequiredIEMissingError{Type: ie.BearerContext}
	}

	bearer.SubscriberIP, err = getSubscriberIP(session.Subscriber)
	if err != nil {
		return err
	}

	cIP := strings.Split(c.LocalAddr().String(), ":")[0]
	uIP := strings.Split(*s5u, ":")[0]
	s5cFTEID := c.NewSenderFTEID(cIP, "").WithInstance(1)
	s5uFTEID := uConn.NewFTEID(gtpv2.IFTypeS5S8PGWGTPU, uIP, "").WithInstance(2)
	s5sgwTEID, err := session.GetTEID(gtpv2.IFTypeS5S8SGWGTPC)
	if err != nil {
		return err
	}
	csRspFromPGW := g2message.NewCreateSessionResponse(
		s5sgwTEID, 0,
		ie.NewCause(gtpv2.CauseRequestAccepted, 0, 0, 0, nil),
		s5cFTEID,
		ie.NewPDNAddressAllocation(bearer.SubscriberIP),
		ie.NewAPNRestriction(gtpv2.APNRestrictionPublic2),
		ie.NewBearerContext(
			ie.NewCause(gtpv2.CauseRequestAccepted, 0, 0, 0, nil),
			ie.NewEPSBearerID(bearer.EBI),
			s5uFTEID,
			ie.NewChargingID(bearer.ChargingID),
		),
	)
	if csReqFromSGW.SGWFQCSID != nil {
		csRspFromPGW.PGWFQCSID = ie.NewFullyQualifiedCSID(cIP, 1)
	}
	session.AddTEID(gtpv2.IFTypeS5S8PGWGTPC, s5cFTEID.MustTEID())
	session.AddTEID(gtpv2.IFTypeS5S8PGWGTPU, s5uFTEID.MustTEID())

	if err := c.RespondTo(sgwAddr, csReqFromSGW, csRspFromPGW); err != nil {
		return err
	}

	s5pgwTEID, err := session.GetTEID(gtpv2.IFTypeS5S8PGWGTPC)
	if err != nil {
		return err
	}
	c.RegisterSession(s5pgwTEID, session)

	// don't forget to activate and add session created to the session list
	if err := session.Activate(); err != nil {
		return err
	}

	go func() {
		buf := make([]byte, 1500)
		for {
			n, raddr, _, err := uConn.ReadFromGTP(buf)
			if err != nil {
				fmt.Printf("error GTPU: %s", err.Error())
				// return
			}
			fmt.Printf("received GTPU: %s", buf)

			rsp := make([]byte, n)
			// update message type and checksum
			copy(rsp, buf[:n])
			rsp[20] = 0
			rsp[22] = 0x9b
			// swap IP
			copy(rsp[12:16], buf[16:20])
			copy(rsp[16:20], buf[12:16])

			if _, err := uConn.WriteToGTP(teidOut, rsp, raddr); err != nil {
				return
			}
		}
	}()

	loggerCh <- fmt.Sprintf("Session created with S-GW for subscriber: %s;\n\tS5C S-GW: %s, TEID->: %#x, TEID<-: %#x, user address: %s",
		session.Subscriber.IMSI, sgwAddr, s5sgwTEID, s5pgwTEID, bearer.SubscriberIP,
	)
	return nil
}

func handleDeleteSessionRequest(c *gtpv2.Conn, sgwAddr net.Addr, genericMsg gtp.Message) error {
	if genericMsg.Version() != 2 {
		return fmt.Errorf("wrong version")
	}
	msg, ok := genericMsg.(g2message.Message)
	if !ok {
		return fmt.Errorf("could not cast message")
	}
	loggerCh <- fmt.Sprintf("Received %s from %s", msg.MessageTypeName(), sgwAddr)

	// assert type to refer to the struct field specific to the message.
	// in general, no need to check if it can be type-asserted, as long as the MessageType is
	// specified correctly in AddHandler().
	session, err := c.GetSessionByTEID(msg.TEID(), sgwAddr)
	if err != nil {
		dsr := g2message.NewDeleteSessionResponse(
			0, 0,
			ie.NewCause(gtpv2.CauseIMSIIMEINotKnown, 0, 0, 0, nil),
		)
		if err := c.RespondTo(sgwAddr, msg, dsr); err != nil {
			return err
		}

		return err
	}

	// respond to S-GW with DeleteSessionResponse.
	teid, err := session.GetTEID(gtpv2.IFTypeS5S8SGWGTPC)
	if err != nil {
		loggerCh <- fmt.Sprintf("Error: %v", err)
		return nil
	}
	dsr := g2message.NewDeleteSessionResponse(
		teid, 0,
		ie.NewCause(gtpv2.CauseRequestAccepted, 0, 0, 0, nil),
	)
	if err := c.RespondTo(sgwAddr, msg, dsr); err != nil {
		return err
	}

	loggerCh <- fmt.Sprintf("Session deleted for Subscriber: %s", session.IMSI)
	c.RemoveSession(session)
	return nil
}
