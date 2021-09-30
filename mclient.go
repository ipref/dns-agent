/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"github.com/ipref/ref"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

const (
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

func print_records(recs []AddrRec) {

	for _, rec := range recs {
		if rec.ip == 0 {
			log.Printf("|   removed:  %v + %v", rec.gw, &rec.ref)
		} else {
			log.Printf("|   new host: %v + %v  ->  %v", rec.gw, &rec.ref, rec.ip)
		}
	}
}

func packet_to_send(req SendReq) []byte {

	var off int

	pkt := make([]byte, MAXPKTLEN)

	// V1 header

	pkt[V1_VER] = V1_SIG
	pkt[V1_CMD] = V1_REQ | V1_MC_HOST_DATA
	be.PutUint16(pkt[V1_PKTID:V1_PKTID+2], <-pktidq)
	pkt[V1_RESERVED] = 0
	pkt[V1_RESERVED+1] = 0

	off = V1_HDR_LEN

	// see if null request

	if len(req.source) == 0 && req.batch == 0 {

		pkt[V1_CMD] = V1_DATA | V1_NOOP
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
		log.Printf("I SEND null packet")
		return pkt[:off]
	}

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

			for off += dnmlen + 2; off&3 != 0; off++ {
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

	if off&3 != 0 {
		log.Fatal("F payload length not divisible by 4")
	}

	be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))

	log.Printf("I SEND records:  %v  batch [%08x]", req.source, req.batch)
	print_records(req.recs)

	return pkt[:off]
}

func parse_packet(pkt []byte) HostReq {

	hreq := HostReq{"", NULL, 0}
	rlen := len(pkt)

	// validate pkt format

	if rlen < 8 {
		log.Printf("E mclient read: pkt to short")
		return hreq
	}

	if pkt[0] != V1_SIG {
		log.Printf("E mclient read: invalid pkt signature: 0x%02x", pkt[V1_VER])
		return hreq
	}

	if rlen&^0x3 != 0 || uint16(rlen/4) != be.Uint16(pkt[V1_PKTLEN:V1_PKTLEN+2]) {
		log.Printf("E mclient read: pkt length(%v) does not match length field(%v)",
			rlen, be.Uint16(pkt[V1_PKTLEN:V1_PKTLEN+2])*4)
		return hreq
	}

	// pkt payload

	var source string
	var batch uint32

	off := V1_HDR_LEN

payload:
	switch pkt[V1_CMD] {
	case V1_DATA | V1_NOOP:
	case V1_ACK | V1_NOOP:
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

		hreq := HostReq{source, ACK, batch}
		hreq.source = source
		hreq.req = ACK
		hreq.batch = batch

		if batch == 0 {
			hreq.req = RESEND
		}

	default:
		log.Printf("E mclient read: unknown pkt type[%02x]", pkt[V1_CMD])
	}

	return hreq
}

func mclient_read(inst uint, conn *net.UnixConn, connerr chan<- string) {

	log.Printf("I mclient read instance(%v) starting", inst)

	for {

		buf := make([]byte, MAXPKTLEN)

		rlen, err := conn.Read(buf[:])

		if err != nil {
			log.Printf("E mclient read instance(%v) io error: %v", inst, err)
			conn.Close()
			sendreqq <- SendReq{"", 0, []AddrRec{}} // force send which will cause mclient write to exit
			break
		}

		if hreq := parse_packet(buf[:rlen]); hreq.req != NULL {
			hostreqq <- hreq
		}
	}

	log.Printf("I mclient read instance(%v) exiting", inst)

	connerr <- "reconnect"
}

func mclient_write(inst uint, conn *net.UnixConn) {

	log.Printf("I mclient write instance(%v) starting", inst)

	for req := range sendreqq {

		pkt := packet_to_send(req)

		_, err := conn.Write(pkt)
		if err != nil {
			log.Printf("E mclient write instance(%v) io error: %v", inst, err)
			conn.Close() // force mclient read to exit
			break
		}
	}

	log.Printf("I mclient write instance(%v) exiting", inst)
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
				print_records(req.recs)
				if rnum := rand.Intn(10); rnum < 7 { // send ACK but not always
					hostreq(req.source, ACK, req.batch, 919*time.Millisecond)
				}
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

	reconn_dly := (cli.poll_ivl * 60) / 7 // mean reconnect delay
	reconnq := make(chan string)

	for inst := uint(1); true; inst++ {

		log.Printf("I connecting to mapper socket: %v", cli.sockname)

		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{cli.sockname, "unixpacket"})

		if err != nil {

			log.Printf("E cannot connect to mapper: %v", err)

		} else {

			connerr := make(chan string)

			go mclient_read(inst, conn, connerr)
			go mclient_write(inst, conn)

			<-connerr // wait for error indications, then try to reconnect
		}

		go func(mean int) {
			dly := time.Second * time.Duration((mean-mean/3)+rand.Intn((mean*2)/3))
			log.Printf("I reconnecting in %v...", dly)
			time.Sleep(dly)
			reconnq <- "reconnect"
		}(reconn_dly)

	drain:
		for { // wait while draining sendreqq
			select {
			case req := <-sendreqq:
				log.Printf("I DISCARD records:  %v  batch [%08x], no connection to mapper", req.source, req.batch)
				print_records(req.recs)
			case <-reconnq:
				break drain
			}
		}
	}

}
