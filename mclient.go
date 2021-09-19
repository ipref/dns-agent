/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"fmt"
	"github.com/ipref/ref"
	"log"
	"math/rand"
	"net"
	"time"
)

const (
	RECONNECT = 17   // [s] delay between reconnect
	MAXPKTLEN = 1280 // max size of packet payload
	// mapper request codes
	GET_CURRENT  = 1
	SEND_CURRENT = 2
	GET_RECORDS  = 3
	SEND_RECORDS = 4
	// pkt constants
	V1_SIG         = 0x11 // v1 signature
	V1_HDR_LEN     = 8
	V1_TYPE_AREC   = 1
	V1_TYPE_STRING = 4
	V1_AREC_LEN    = 4 + 4 + 4 + 8 + 8 // ea + ip + gw + rel.h + ref.l
	// pkt types
	V1_GET_SOURCE_INFO    = 6
	V1_SOURCE_INFO        = 7
	V1_GET_SOURCE_RECORDS = 8
	V1_SOURCE_RECORDS     = 9
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
var pktid chan uint16

func gen_pktid() {

	for id := uint16(new_batchid()); true; id++ {

		if id == 0 {
			id++
		}
		pktid <- id
	}
}

// only in devmode
func drain_sendreqq() {

	for req := range sendreqq {

		log.Printf("SEND RECORDS:  %v  batch[%08x]", req.source, req.batch)
		for _, rec := range req.recs {
			log.Printf("|   %v + %v  ->  %v", rec.gw, &rec.ref, rec.ip)
		}
		if rnum := rand.Intn(10); rnum < 7 { // send ACK but not always
			hostreq(req.source, ACK, req.batch, 919*time.Millisecond)
		}
		hostreq(req.source, EXPIRE, req.batch, DLY_EXPIRE)
	}
}

func send_to_mapper(conn *net.UnixConn, connerr chan<- string, req SendReq) {
	/*
		var pkt [MAXPKTLEN]byte
		var wlen int
		var off int

		switch req.cmd {
		case SEND_CURRENT:

			if minlen := 8 + 4 + 8 + len(req.data.(MreqSendCurrent).source) + 6; len(pkt) < minlen {
				log.Printf("ERR  mclient write: packet buffer too short %v, needs %v",
					len(pkt), minlen)
				return
			}

			source_len := len(req.data.(MreqSendCurrent).source)

			if source_len > 255 {
				log.Printf("ERR  mclient write: source name too long: %v",
					req.data.(MreqSendCurrent).source)
				return
			}

			// header

			pkt[0] = V1_SIG
			pkt[1] = V1_SOURCE_INFO
			be.PutUint16(pkt[2:4], <-pktid)
			pkt[4] = 0
			pkt[5] = 0

			// source info

			off = 8
			be.PutUint32(pkt[off+0:off+4], uint32(req.data.(MreqSendCurrent).count))
			be.PutUint64(pkt[off+4:off+12], req.data.(MreqSendCurrent).hash)
			pkt[off+12] = V1_TYPE_STRING
			pkt[off+13] = byte(source_len)
			copy(pkt[off+14:], req.data.(MreqSendCurrent).source)
			off += 14

			// send the packet

			for wlen = off + source_len; wlen&0x3 != 0; wlen++ {
				pkt[wlen] = 0
			}

			be.PutUint16(pkt[6:8], uint16(wlen/4))

			_, err := conn.Write(pkt[:wlen])
			if err != nil {
				// this will lead to re-connect and recreation of goroutines
				connerr <- fmt.Sprintf("write error: %v", err)
				return
			}

		case SEND_RECORDS:

			if minlen := 8 + (4 + 4 + 4) + V1_AREC_LEN; len(pkt) < minlen {
				log.Printf("ERR  mclient write: packet buffer too short %v, needs %v",
					len(pkt), minlen)
				return
			}

			arecs := req.data.(MreqSendRecords).arecs
			nrecs := len(arecs)

			for ix := 0; ix < nrecs; {

				// headers

				pkt[0] = V1_SIG
				pkt[1] = V1_SOURCE_RECORDS
				be.PutUint16(pkt[2:4], <-pktid)
				pkt[4] = 0
				pkt[5] = 0

				be.PutUint32(pkt[8:12], uint32(req.data.(MreqSendRecords).oid))
				be.PutUint32(pkt[12:16], uint32(req.data.(MreqSendRecords).mark))
				pkt[16] = V1_TYPE_AREC
				pkt[17] = V1_AREC_LEN

				// records

				off = 20
				maxrecs := (len(pkt) - off) / V1_AREC_LEN
				count := nrecs - ix
				if count > maxrecs {
					count = maxrecs
				}

				for maxix := ix + count; ix < maxix; ix++ {

					be.PutUint32(pkt[off:off+4], uint32(arecs[ix].ea))
					be.PutUint32(pkt[off+4:off+8], uint32(arecs[ix].ip))
					be.PutUint32(pkt[off+8:off+12], uint32(arecs[ix].gw))
					be.PutUint64(pkt[off+12:off+20], arecs[ix].ref.H)
					be.PutUint64(pkt[off+20:off+28], arecs[ix].ref.L)
					off += V1_AREC_LEN
				}

				// send the packet

				wlen = off
				be.PutUint16(pkt[18:20], uint16(count))
				be.PutUint16(pkt[6:8], uint16(wlen/4))

				_, err := conn.Write(pkt[:wlen])
				if err != nil {
					// this will lead to re-connect and recreation of goroutines
					connerr <- fmt.Sprintf("write error: %v", err)
					return
				}
			}

		default:
			log.Printf("ERR  mclient write: unknown pkt type: %v", req.cmd)
		}
	*/
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
		log.Printf("ERR  mclient read: pkt to short")
		return
	}

	pkt := buf[:rlen]

	if pkt[0] != V1_SIG {
		log.Printf("ERR  mclient read: invalid pkt signature: 0x%02x", pkt[0])
		return
	}

	if rlen&^0x3 != 0 || uint16(rlen/4) != be.Uint16(pkt[6:8]) {
		log.Printf("ERR  mclient read: pkt length(%v) does not match length field(%v)",
			rlen, be.Uint16(pkt[6:8])*4)
		return
	}
	/*
		// pkt payload

		cmd := pkt[1] &^ 0x3f
		//mode := pkt[1] >> 6
		//pktid := be.Uint16(pkt[2:4])
		msg := pkt[8:]

		switch cmd {
		case V1_GET_SOURCE_INFO:

			mreq := new(MreqData)
			mreq.cmd = GET_CURRENT

			mreqq <- mreq

		case V1_GET_SOURCE_RECORDS:

			if len(msg) < 4+4+8+4 { // oid + mark + hash + minimal source
				log.Printf("ERR  mclient read: get record pkt too short")
				return
			}

			if msg[16] != V1_TYPE_STRING {
				log.Printf("ERR  mclient read: get record invalid string type")
				return
			}

			if 8+4+4+8+((int(msg[17])+2+3)/4)*4 != rlen {
				log.Printf("ERR  mclient read: get record invalid string length(%v)", msg[17])
				return
			}

			mreq := new(MreqData)
			mreq.cmd = GET_RECORDS
			mreq.data = MreqGetRecords{
				O32(be.Uint32(msg[8:12])),
				M32(be.Uint32(msg[12:16])),
				be.Uint64(msg[16:24]),
				string(msg[18 : 18+int(msg[17])]),
			}

			mreqq <- mreq

		default:
			log.Printf("ERR  mclient read: unknown pkt type(%v)", cmd)
		}
	*/
}

func mclient_read(conn *net.UnixConn, connerr chan<- string, quit <-chan int) {

	log.Printf("mclient read starting")

	for {
		select {
		case <-quit:
			log.Printf("mclient read quitting")
			return
		default:
			read_from_mapper(conn, connerr)
		}
	}
}

func mclient_write(conn *net.UnixConn, connerr chan<- string, quit <-chan int) {

	log.Printf("mclient write starting")

	for {
		select {
		case <-quit:
			log.Printf("mclient write quitting")
			return
		case req := <-sendreqq:
			send_to_mapper(conn, connerr, req)
		}
	}
}

// Start new mclient. In case of reconnect, the old client will quit and
// disappear along with old conn and channels.
func mclient_conn() {

	if cli.devmode {
		go drain_sendreqq()
		return
	}

	pktid = make(chan uint16, SENDREQQLEN)
	go gen_pktid()

	for {
		log.Printf("connecting to mapper socket: %v", cli.sockname)

		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{cli.sockname, "unixpacket"})

		if err != nil {
			log.Printf("ERR  cannot connect to mapper: %v", err)
		} else {

			connerr := make(chan string, 2) // as many as number of spawned goroutines
			quit := make(chan int)

			go mclient_read(conn, connerr, quit)
			go mclient_write(conn, connerr, quit)

			// Now wait for error indications, then try to reconnect

			errmsg := <-connerr
			log.Printf("ERR  connection to mapper: %v", errmsg)
			close(quit)
			conn.Close()
		}

		log.Printf("reconnecting in %v secs...", RECONNECT)
		time.Sleep(time.Duration(time.Second * RECONNECT))
	}

}
