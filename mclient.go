/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"errors"
	. "github.com/ipref/common"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

const (
	MAXPKTLEN = 1200 // max size of packet payload
)

type SendReq struct {
	cmd     byte
	source  string
	qrmhash uint64
	batch   uint32
	recs    []AddrRec // .EA should be the zero address (same IP ver as .IP)
}

var sendreqq chan SendReq
var pktidq chan uint16

func print_records(recs []AddrRec) {

	for _, rec := range recs {
		log.Printf(":   host: %v + %v  ->  %v", rec.GW, &rec.Ref, rec.IP)
	}
}

// helper function, pkt space must be guaranteed by the caller
func insert_source(source string, pkt []byte) int {

	off := 0

	for _, src := range strings.Split(source, ":") {

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

	return off
}

func packet_to_send(req SendReq) []byte {

	var off int

	pkt := make([]byte, MAXPKTLEN)

	// V1 header

	pkt[V1_VER] = V1_SIG
	pkt[V1_CMD] = req.cmd
	be.PutUint16(pkt[V1_PKTID:V1_PKTID+2], <-pktidq)
	pkt[V1_IPVER] = byte(cli.ea_ipver << 4) | byte(cli.gw_ipver)
	pkt[V1_RESERVED] = 0

	off = V1_HDR_LEN

	switch pkt[V1_CMD] {

	case V1_DATA | V1_NOOP:

		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
		log.Printf("I SEND null packet")

	case V1_REQ | V1_MC_HOST_DATA:

		// batch id and hash

		be.PutUint32(pkt[off+V1_HOST_DATA_BATCHID:off+V1_HOST_DATA_BATCHID+4], req.batch)
		be.PutUint64(pkt[off+V1_HOST_DATA_HASH:off+V1_HOST_DATA_HASH+8], req.qrmhash)

		off += V1_HOST_DATA_SOURCE

		// source

		off += insert_source(req.source, pkt[off:])

		// records

		for _, rec := range req.recs {

			if rec.EA.Ver() != cli.ea_ipver || rec.GW.Ver() != cli.gw_ipver {
				panic("unexpected")
			}
			rec.Encode(pkt[off:])
			off += rec.EncodedLen()
		}

		// send the packet

		if off&3 != 0 {
			log.Fatal("F payload length not divisible by 4")
		}

		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))

		log.Printf("I SEND records(%v):  %v  hash[%016x]  batch [%08x]",
			len(req.recs), req.source, req.qrmhash, req.batch)
		print_records(req.recs)

	case V1_REQ | V1_MC_HOST_DATA_HASH:

		// count and hash

		be.PutUint32(pkt[off+V1_HOST_DATA_COUNT:off+V1_HOST_DATA_COUNT+4], req.batch)
		be.PutUint64(pkt[off+V1_HOST_DATA_HASH:off+V1_HOST_DATA_HASH+8], req.qrmhash)

		off += V1_HOST_DATA_SOURCE

		// source

		off += insert_source(req.source, pkt[off:])

		// send the packet

		if off&3 != 0 {
			log.Fatal("F payload length not divisible by 4")
		}

		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))

		log.Printf("I SEND HASH:  %v  hash(%v)[%016x]", req.source, req.batch, req.qrmhash)

	default:

		pkt[V1_CMD] = V1_DATA | V1_NOOP
		be.PutUint16(pkt[V1_PKTLEN:V1_PKTLEN+2], uint16(off/4))
		log.Printf("E SEND null packet in lieu of an unknown send request")
	}

	return pkt[:off]
}

// helper function, caller must validate packet
func parse_source(pkt []byte) (string, int, error) {

	off := 0
	source := ""
	rlen := len(pkt)

	for ix := 0; ix < 2; ix++ {

		if rlen <= off+4 {
			return "", 0, errors.New("invalid source string")
		}

		if pkt[off] != V1_TYPE_STRING || rlen < (off+int(pkt[off+1])+5)&^3 {
			return "", 0, errors.New("invalid source string length")
		}

		source += string(pkt[off+2:off+2+int(pkt[off+1])]) + ":"

		off += (int(pkt[off+1]) + 5) &^ 3
	}

	source = source[:len(source)-1] // strip right colon

	return source, off, nil
}

func parse_packet(pkt []byte) HostReq {

	hreq := HostReq{NULL, "", 0, 0}
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

	if rlen&0x3 != 0 || uint16(rlen/4) != be.Uint16(pkt[V1_PKTLEN:V1_PKTLEN+2]) {
		log.Printf("E mclient read: pkt length(%v) does not match length field(%v)",
			rlen, be.Uint16(pkt[V1_PKTLEN:V1_PKTLEN+2])*4)
		return hreq
	}

	// pkt payload

	var source string
	var err error

	off := V1_HDR_LEN

	switch pkt[V1_CMD] {
	case V1_DATA | V1_NOOP:
	case V1_ACK | V1_NOOP:
	case V1_ACK | V1_MC_HOST_DATA:

		hreq.batch = be.Uint32(pkt[off+V1_HOST_DATA_BATCHID : off+V1_HOST_DATA_BATCHID+4])
		hreq.qrmhash = be.Uint64(pkt[off+V1_HOST_DATA_HASH : off+V1_HOST_DATA_HASH+8])

		off += V1_HOST_DATA_SOURCE

		source, _, err = parse_source(pkt[off:])

		if err == nil {
			hreq.source = source
			hreq.req = ACK
		} else {
			log.Printf("E mclient read: %v, dropping packet", err)
		}

	case V1_ACK | V1_MC_HOST_DATA_HASH, V1_NACK | V1_MC_HOST_DATA_HASH:

		hreq.batch = be.Uint32(pkt[off+V1_HOST_DATA_COUNT : off+V1_HOST_DATA_COUNT+4])
		hreq.qrmhash = be.Uint64(pkt[off+V1_HOST_DATA_HASH : off+V1_HOST_DATA_HASH+8])

		off += V1_HOST_DATA_SOURCE

		source, _, err = parse_source(pkt[off:])

		if err == nil {
			hreq.source = source
			switch pkt[V1_CMD] & 0xc0 {
			case V1_ACK:
				hreq.req = ACK_HASH
			case V1_NACK:
				hreq.req = NACK_HASH
			default:
				log.Printf("E mclient read: invalid pkt type[%02x], dropping packet", pkt[V1_CMD])
			}
		} else {
			log.Printf("E mclient read: %v, dropping packet", err)
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
			sendreqq <- SendReq{V1_DATA | V1_NOOP, "", 0, 0, []AddrRec{}} // force send which will cause mclient write to exit
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
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("E mclient write instance(%v) io error: %v", inst, err)
			}
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

				switch req.cmd {

				case V1_REQ | V1_MC_HOST_DATA:

					log.Printf("I SEND records(%v) (devmode):  %v  hash[%016x]  batch [%08x]",
						len(req.recs), req.source, req.qrmhash, req.batch)
					print_records(req.recs)
					if rnum := rand.Intn(10); rnum < 7 { // send ACK but not always
						hostreq(ACK, req.source, req.batch, req.qrmhash, 919*time.Millisecond)
					}

				case V1_REQ | V1_MC_HOST_DATA_HASH:

					log.Printf("I SEND HASH (devmode):  %v  hash(%v)[%016x]",
						req.source, req.batch, req.qrmhash)

				default:

					log.Printf("I SEND something else (devmode):  cmd[%02x]", req.cmd)
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

		go func() {
			dly := time.Second * time.Duration(10)
			log.Printf("I reconnecting in %v...", dly)
			time.Sleep(dly)
			reconnq <- "reconnect"
		}()

	drain:
		for { // wait while draining sendreqq
			select {

			case req := <-sendreqq:

				switch req.cmd {

				case V1_REQ | V1_MC_HOST_DATA:

					log.Printf("I DISCARD records:  %v  hash[%016x]  batch[%08x], no connection to mapper",
						req.source, req.qrmhash, req.batch)

				case V1_REQ | V1_MC_HOST_DATA_HASH:

					log.Printf("I DISCARD hash:  %v  hash(%v)[%016x], no connection to mapper",
						req.source, req.batch, req.qrmhash)

				default:

					log.Printf("I DISCARD packet (devmode):  cmd[%02x]", req.cmd)
				}

			case <-reconnq:

				break drain
			}
		}
	}

}
