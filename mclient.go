/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"fmt"
	"github.com/ipref/ref"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

const (
	RECONNECT = 97   // [s] delay between reconnect
	MAXPKTLEN = 1200 // max size of packet payload
)

const ( // v1 constants

	V1_SIG      = 0x11 // v1 signature
	V1_HDR_LEN  = 8
	V1_AREC_LEN = 4 + 4 + 4 + 8 + 8 // ea + ip + gw + ref.h + ref.l
	// v1 header offsets
	V1_VER      = 0
	V1_CMD      = 1
	V1_PKTID    = 2
	V1_RESERVED = 4
	V1_PKTLEN   = 6
	// v1 arec offsets
	V1_AREC_EA   = 0
	V1_AREC_IP   = 4
	V1_AREC_GW   = 8
	V1_AREC_REFH = 12
	V1_AREC_REFL = 20
)

const ( // v1 item types

	//V1_TYPE_NONE   = 0
	//V1_TYPE_AREC   = 1
	//V1_TYPE_SOFT   = 2
	//V1_TYPE_IPV4   = 3
	V1_TYPE_STRING = 4
)

const ( // v1 commands

	V1_NOOP             = 0
	V1_MC_HOST_DATA     = 14
	V1_MC_GET_HOST_DATA = 15
)

const ( // v1 command mode, top two bits

	V1_DATA = 0x00
	V1_REQ  = 0x40
	V1_ACK  = 0x80
	V1_NACK = 0xC0
)

type AddrRec struct {
	ip  IP32
	gw  IP32
	ref ref.Ref
}

type SendReq struct {
	source string
	batch  uint32
	recs   []AddrRec
}

var sendreqq chan SendReq
var pktidq chan uint16

func send_to_mapper(conn *net.UnixConn, connerr chan<- string, req SendReq) {

	var pkt [MAXPKTLEN]byte
	var off int

	// V1 header

	pkt[V1_VER] = V1_SIG
	pkt[V1_CMD] = V1_REQ | V1_MC_HOST_DATA
	be.PutUint16(pkt[V1_PKTID:V1_PKTID+2], <-pktidq)
	pkt[V1_RESERVED] = 0
	pkt[V1_RESERVED+1] = 0

	off = V1_HDR_LEN

	// batch id

	be.PutUint32(pkt[off:off+4], req.batch)

	off += 4

	// source

	for _, src := range strings.Split(req.source, ":") {

		dnm := []byte(src)
		dnmlen := len(dnm)

		if 0 < dnmlen && dnmlen < 256 { // should be true since DNS names are shorter than 255 chars

			pkt[off] = V1_TYPE_STRING
			pkt[off+1] = byte(dnmlen)
			copy(pkt[off+2:], dnm)

			for off += dnmlen + 2; off < (dnmlen+5)&^3; off++ {
				pkt[off] = 0
			}

		} else {
			log.Fatal("F dns name too long(%v): %v", dnmlen, src)
		}
	}

	// records

	for _, rec := range req.recs {

		be.PutUint32(pkt[off+V1_AREC_EA:off+V1_AREC_EA+4], uint32(0))
		be.PutUint32(pkt[off+V1_AREC_IP:off+V1_AREC_IP+4], uint32(rec.ip))
		be.PutUint32(pkt[off+V1_AREC_GW:off+V1_AREC_GW+4], uint32(rec.gw))
		be.PutUint64(pkt[off+V1_AREC_REFH:off+V1_AREC_REFH+8], uint64(rec.ref.H))
		be.PutUint64(pkt[off+V1_AREC_REFL:off+V1_AREC_REFL+8], uint64(rec.ref.L))
		off += V1_AREC_LEN
	}

	// send the packet

	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))

	_, err := conn.Write(pkt[:off])
	if err != nil {
		// this will lead to re-connect and recreation of goroutines
		connerr <- fmt.Sprintf("write error: %v", err)
		return
	}

}

func read_from_mapper(conn *net.UnixConn, connerr chan<- string) {

	var buf [MAXPKTLEN]byte

	rlen, err := conn.Read(buf[:])
	if err != nil {
		// this will lead to re-connect and recreation of goroutines
		connerr <- fmt.Sprintf("read error: %v", err)
		return
	}

	// validate pkt format

	if rlen < 8 {
		log.Printf("E mclient read: pkt to short")
		return
	}

	pkt := buf[:rlen]

	if pkt[0] != V1_SIG {
		log.Printf("E mclient read: invalid pkt signature: 0x%02x", pkt[V1_VER])
		return
	}

	if rlen&^0x3 != 0 || uint16(rlen/4) != be.Uint16(pkt[V1_PKTLEN:V1_PKTLEN+2]) {
		log.Printf("E mclient read: pkt length(%v) does not match length field(%v)",
			rlen, be.Uint16(pkt[V1_PKTLEN:V1_PKTLEN+2])*4)
		return
	}

	// pkt payload

	var source string
	var batch uint32

	off := V1_HDR_LEN

payload:
	switch pkt[V1_CMD] {
	case V1_ACK | V1_MC_HOST_DATA:

		batch = be.Uint32(pkt[off : off+4])

		fallthrough

	case V1_DATA | V1_MC_GET_HOST_DATA:

		off += 4

		for off < len(pkt) {

			if pkt[off] != V1_TYPE_STRING {
				log.Printf("E mclient read: missing source string")
				break payload
			}

			slen := int(pkt[off+1])
			source += string(pkt[off+2:off+2+slen]) + ":"
			off += (slen + 5) & ^3
		}

		source = strings.TrimSuffix(source, ":")

		req := HostReq{source, ACK, batch}
		if batch == 0 {
			req.req = RESEND
		}

		hostreqq <- req

	default:
		log.Printf("E mclient read: unknown pkt type(%v)", pkt[V1_CMD])
	}
}

func mclient_read(order uint, conn *net.UnixConn, connerr chan<- string, quit <-chan int) {

	log.Printf("I mclient read starting order(%v)", order)

	for {
		select {
		case <-quit:
			log.Printf("I mclient read quitting order(%v)", order)
			return
		default:
			read_from_mapper(conn, connerr)
		}
	}
}

func mclient_write(order uint, conn *net.UnixConn, connerr chan<- string, quit <-chan int) {

	log.Printf("I mclient write starting order(%v)", order)

	for {
		select {
		case <-quit:
			log.Printf("I mclient write quitting order(%v)", order)
			return
		case req := <-sendreqq:
			log.Printf("I SEND records:  %v  batch [%08x]", req.source, req.batch)
			for _, rec := range req.recs {
				if rec.ip == 0 {
					log.Printf("|   removed:  %v + %v", rec.gw, &rec.ref)
				} else {
					log.Printf("|   new host: %v + %v  ->  %v", rec.gw, &rec.ref, rec.ip)
				}
			}
			send_to_mapper(conn, connerr, req)
		}
	}
}

// Start new mclient (mapper client). In case of reconnect, the old client will
// quit and disappear along with old conn and channels.
func mclient_conn() {

	// if devmode, don't connect, drain the queue and feed back responses
	// internally instead

	if cli.devmode {

		go func() {

			for req := range sendreqq {

				log.Printf("I SEND records:  %v  batch [%08x]", req.source, req.batch)
				for _, rec := range req.recs {
					if rec.ip == 0 {
						log.Printf("|   removed:  %v + %v", rec.gw, &rec.ref)
					} else {
						log.Printf("|   new host: %v + %v  ->  %v", rec.gw, &rec.ref, rec.ip)
					}
				}
				if rnum := rand.Intn(10); rnum < 7 { // send ACK but not always
					hostreq(req.source, ACK, req.batch, 919*time.Millisecond)
				}
				hostreq(req.source, EXPIRE, req.batch, DLY_EXPIRE)
			}
		}()

		return
	}

	// start pktid generator

	pktidq = make(chan uint16, SENDREQQLEN)

	go func() {

		for id := uint16(new_batchid()); true; id++ {

			if id == 0 {
				id++
			}
			pktidq <- id
		}
	}()

	// connect to mapper

	for order := uint(1); true; order++ {

		log.Printf("I connecting to mapper socket: %v", cli.sockname)

		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{cli.sockname, "unixpacket"})

		if err != nil {
			log.Printf("E cannot connect to mapper: %v", err)
		} else {

			connerr := make(chan string, 2) // as many as number of spawned goroutines
			quit := make(chan int)

			go mclient_read(order, conn, connerr, quit)
			go mclient_write(order, conn, connerr, quit)

			// Now wait for error indications, then try to reconnect

			errmsg := <-connerr
			log.Printf("E connection to mapper: %v", errmsg)
			close(quit)
			conn.Close()
		}

		log.Printf("I reconnecting in %v secs...", RECONNECT)

	drain:
		for { // wait while draining sendreqq
			select {
			case req := <-sendreqq:
				log.Printf("I DISCARD records:  %v  batch [%08x], no connection to mapper", req.source, req.batch)
				for _, rec := range req.recs {
					if rec.ip == 0 {
						log.Printf("|   removed:  %v + %v", rec.gw, &rec.ref)
					} else {
						log.Printf("|   new host: %v + %v  ->  %v", rec.gw, &rec.ref, rec.ip)
					}
				}
			case <-time.After(time.Second * RECONNECT):
				break drain
			}
		}
	}

}
