/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

const (
	RECONNECT = 17 // [s] delay between reconnect
	MAXPKTLEN = 16384
	// mapper request codes
	GET_CURRENT  = 1
	SEND_CURRENT = 2
	GET_RECORDS  = 3
	SEND_RECORDS = 4
	// pkt constants
	V1_SIG         = 0x11 // v1 signature
	V1_TYPE_AREC   = 1
	V1_TYPE_STRING = 4
	V1_AREC_LEN    = 4 + 4 + 4 + 8 + 8 // ea + ip + gw + rel.h + ref.l
	// pkt types
	V1_GET_SOURCE_INFO    = 6
	V1_SOURCE_INFO        = 7
	V1_GET_SOURCE_RECORDS = 8
	V1_SOURCE_RECORDS     = 9
)

type MreqSendCurrent struct {
	count  int
	hash   uint64
	source string
}

type MreqSendRecords struct {
	oid    O32
	mark   M32
	hash   uint64
	source string
	arecs  []AddrRec
}

type MreqGetRecords struct {
	oid    O32
	mark   M32
	hash   uint64
	source string
}

type MreqData struct {
	cmd  byte
	data interface{}
}

var mclientq chan (*MreqData)
var pktid chan uint16

func gen_pktid() {

	for id := 0; true; id++ {

		if id == 0 {
			id++
		}
		pktid <-id
	}
}

func send_to_mapper(conn *net.UnixConn, connerr chan<- string, req *MreqData) {

	var pkt [MAXPKTLEN]byte
	var wlen int
	var off int

	switch req.cmd {
	case SEND_CURRENT:

		if minlen := 8 + 4 + 8 + len(req.(MreqSendCurrent).source) + 6; len(pkt) < minlen {
			log.Printf("ERR  mclient write: packet buffer too short %v, needs %v",
				len(pkt), minlen)
			return
		}

		source_len := len(req.(MreqSendCurrent).source)

		if source_len > 255 {
			log.Printf("ERR  mclient write: source name too long: %v",
				req.(MreqSendCurrent).source)
			return
		}

		// header

		pkt[0] = V1_SIG
		pkt[1] = V1_SOURCE_INFO
		be.PutUint16(pkt[2:4],  <-pktid)
		pkt[4] = 0
		pkt[5] = 0

		// source info

		off = 8
		be.PutUint32(pkt[off+0:off+4], uint32(req.(MreqSendCurrent).count))
		be.PutUint64(pkt[off+4:off+12], req.(MreqSendCurrent).hash)
		pkt[off+12] = V1_TYPE_STRING
		pkt[off+13] = byte(source_len)
		copy(pkt[off+14:], req.(MreqSendCurrent).source)
		off += 14

		// send the packet

		for wlen = off + source_len;  wlen&0x3 != 0; wlen++ {
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

		arecs := rec.(MreqSendRecords).arecs
		nrecs := len(arecs)

		for ix := 0; ix < nrecs; {

			// headers

			pkt[0] = V1_SIG
			pkt[1] = V1_SOURCE_RECORDS
			be.PutUint16(pkt[2:4],  <-pktid)
			pkt[4] = 0
			pkt[5] = 0

			be.PutUint32(pkt[8:12], uint32(rec.(MreqSendRecords).oid))
			be.PutUint32(pkt[12:16], uint32(rec.(MreqSendRecords).mark))
			pkt[16] = V1_TYPE_AREC
			pkt[17] = V1_AREC_LEN

			// records

			off = 20
			maxrecs := (len(pkt) - off)/V1_AREC_LEN
			count := nrcs - ix
			if count > maxrecs {
				count = maxrecs
			}

			for ; ix < ix + count; ix++, off += V1_AREC_LEN {

				be.PutUint32(pkt[off:off+4], uint32(arecs[ix].ea))
				be.PutUint32(pkt[off+4:off+8], uint32(arecs[ix].ip))
				be.PutUint32(pkt[off+8:off+12], uint32(arecs[ix].gw))
				be.PutUint64(pkt[off+12:off+20], arecs[ix].ref.h)
				be.PutUint64(pkt[off+20:off+28], arecs[ix[.ref.l)
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
		case req := <-mclientq:
			send_to_mapper(conn, connerr, req)
		}
	}
}

// Start new mclient. In case of reconnect, the old client will quit and
// disappear along with old conn and channels.
func mclient_conn() {

	pktid = make(chan uint16, MCLIENTQLEN)
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

/*
func send_to_mapper(m *MapperConn, dnm string, gw net.IP, ref ref.Ref) error {

	if m.conn == nil {
		conn, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{cli.sockname, "unixpacket"})
		if err != nil {
			return fmt.Errorf("cannot connect to mapper: %v", err)
		}
		m.conn = conn
	}

	var msg [MSGMAX]byte
	var err error

	// header

	m.msgid += 1
	wlen := 4

	msg[0] = 0x40 + MQP_INFO_AA
	msg[1] = m.msgid
	msg[2] = 0
	msg[3] = 0

	// dnm

	dnmlen := len(dnm)
	if dnmlen > 255 {
		return fmt.Errorf("invalid domain name (too long): %v", dnm)
	}
	msg[4] = byte(dnmlen)
	copy(msg[5:], dnm)
	wlen += (dnmlen + 4) &^ 3
	for ii := 5 + dnmlen; ii < wlen; ii++ {
		msg[ii] = 0 // pad with zeros
	}

	// gw

	gwlen := len(gw)
	if gwlen != 4 && gwlen != 16 {
		return fmt.Errorf("invalid GW address length: %v", gwlen)
	}

	copy(msg[wlen:], gw)
	wlen += gwlen
	msg[2] = byte((gwlen >> 2) << 4)

	// ref

	if ref.H != 0 {
		be.PutUint64(msg[wlen:wlen+8], ref.H)
		wlen += 8
	}

	be.PutUint64(msg[wlen:wlen+8], ref.L)
	wlen += 8

	msg[3] = byte(wlen) / 4

	// Don't wait more than half a second

	err = m.conn.SetDeadline(time.Now().Add(time.Millisecond * 500))
	if err != nil {
		return fmt.Errorf("cannot set mapper request deadline: %v", err)
	}

	// send request to mapper

	_, err = m.conn.Write(msg[:wlen])
	if err != nil {
		m.conn.Close()
		m.conn = nil
		return fmt.Errorf("map request send error: %v", err)
	}

	// read response

	rlen, err := m.conn.Read(msg[:])
	if err != nil {
		m.conn.Close()
		m.conn = nil
		return fmt.Errorf("map request receive error: %v", err)
	}

	if rlen < 4 {
		return fmt.Errorf("response from mapper too short")
	}

	if msg[0] != 0x80+MQP_INFO_AA {
		return fmt.Errorf("map request declined by mapper")
	}

	if rlen != int(msg[3])*4 {
		return fmt.Errorf("malformed response from mapper")
	}

	if msg[1] != m.msgid {
		return fmt.Errorf("mapper response out of sequence")
	}

	return nil
}
*/
