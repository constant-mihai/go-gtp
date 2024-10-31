// Copyright 2019-2024 go-gtp authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

// Command pgw is a dead simple implementation of P-GW only with GTP-related features.
//
// This example is not maintained well. Please see example/gw-tester/pgw for better implementation.
//
// P-GW follows the steps below if there's no unexpected events in the middle. Note
// that the Gx procedure is just mocked to make it work in standalone manner.
//
// 1. Wait for Create Session Request from S-GW.
//
// 2. Send Create Session Response to S-GW if the required IEs are not missing, and
// start listening on the interface specified with s5u flag.
//
// 3. If Modify Bearer Request comes from S-GW, update bearer information.
//
// 4. If T-PDU comes from S-GW, print the payload of encapsulated packets received,
// and respond to it with payload(ICMP Echo Reply).
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/wmnsk/go-gtp/gtpv1"
	g1message "github.com/wmnsk/go-gtp/gtpv1/message"
	"github.com/wmnsk/go-gtp/gtpv2"
	g2message "github.com/wmnsk/go-gtp/gtpv2/message"
)

// command-line arguments
var (
	s5c = flag.String("s5c", "127.0.0.52:2123", "IP for S5-C interface.")
	s5u = flag.String("s5u", "127.0.0.4:2152", "IP for S5-U interface.")
)

func main() {
	flag.Parse()
	log.SetPrefix("[P-GW] ")

	startIMSIString := os.Getenv("START_IMSI")
	startIMSI, err := strconv.Atoi(startIMSIString)
	if err != nil {
		log.Fatal(err)
	}

	populateSubscribers(startIMSI)

	// for k, v := range subIPMap {
	// 	fmt.Printf("imsi: %s, ip: %s\n", k, v)
	// }

	s5cAddr, err := net.ResolveUDPAddr("udp", *s5c)
	if err != nil {
		log.Println(err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// start listening on the specified IP:Port.
	s5cConn := gtpv2.NewConn(s5cAddr, gtpv2.IFTypeS5S8PGWGTPC, 0)
	s5cConn.DisableValidation()
	go func() {
		if err := s5cConn.ListenAndServe(ctx); err != nil {
			log.Println(err)
			return
		}
	}()
	log.Printf("Started serving C-Plane on %s", s5cAddr)

	// register handlers for ALL the message you expect remote endpoint to send.
	s5cConn.AddHandlers(map[uint8]gtpv2.HandlerFunc{
		g2message.MsgTypeCreateSessionRequest:    handleCreateSessionRequest,
		g2message.MsgTypeDeleteSessionRequest:    handleDeleteSessionRequest,
		g1message.MsgTypeCreatePDPContextRequest: handleCreatePdpContextRequest,
		g1message.MsgTypeDeletePDPContextRequest: handleDeletePdpContextRequest,
	})

	s5uAddr, err := net.ResolveUDPAddr("udp", *s5u)
	if err != nil {
		log.Println(err)
		return
	}

	uConn = gtpv1.NewUPlaneConn(s5uAddr)
	defer uConn.Close()

	go func() {
		if err = uConn.ListenAndServe(ctx); err != nil {
			log.Println(err)
			return
		}
	}()
	log.Printf("Started serving U-Plane on %s", s5uAddr)

	for {
		select {
		case str := <-loggerCh:
			log.Printf("%s", str)
		case err := <-errCh:
			log.Printf("Warning: %s", err)
		case <-time.After(10 * time.Second):
			var activeIMSIs []string
			for _, sess := range s5cConn.Sessions() {
				if !sess.IsActive() {
					continue
				}
				activeIMSIs = append(activeIMSIs, sess.IMSI)
			}
			if len(activeIMSIs) == 0 {
				continue
			}

			log.Println("Active Subscribers:")
			for _, imsi := range activeIMSIs {
				log.Printf("\t%s", imsi)
			}
			activeIMSIs = nil
		}
	}
}
