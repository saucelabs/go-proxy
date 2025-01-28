// Copyright 2022-2024 Sauce Labs Inc., all rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"flag"
	"log"
	"net"
)

var (
	address = flag.String("address", "0.0.0.0:5005", "UDP address to listen on")
	bufSize = flag.Int("bufsize", 1024, "Size of the buffer to read data into")
)

func main() {
	log.Println("Listening on UDP port", *address)

	conn, err := net.ListenPacket("udp", *address)
	if err != nil {
		log.Fatalf("Error starting UDP listener: %s", err)
	}
	defer conn.Close()

	msgCnt := uint64(0)
	buffer := make([]byte, *bufSize)
	for {
		msgCnt++

		n, caddr, err := conn.ReadFrom(buffer)
		if err != nil {
			log.Printf("Error reading from connection: %s", err)
			continue
		}
		log.Printf("Recv(%d) %s: %s\n", msgCnt, caddr, string(buffer[:n]))

		if _, err := conn.WriteTo(buffer[:n], caddr); err != nil {
			log.Printf("Error writing to connection %s: %s", caddr, err)
		}
	}
}
