/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"encoding/binary"
	"github.com/ipref/ref"
	"net"
	"strings"
)

const (
	MQP_PING    = 1
	MQP_MAP_EA  = 2
	MQP_INFO_AA = 3
	MSGMAX      = 320 // 255 + 1 + 16 + 16 + 16 + 4 = 308 rounded up to 16 byte boundary
)

var be = binary.BigEndian

type M32 int32   // mark, a monotonic counter
type O32 int32   // owner id, an index into array
type IP32 uint32 // ip address

type AddrRec struct {
	ea   IP32
	ip   IP32
	gw   IP32
	ref  ref.Ref
	host string
}

type ZoneData struct {
	ipref_zone string
	local_zone string
	hash       uint64
	arecs      []AddrRec
}

func (zd *ZoneData) sig() string {
	return strings.TrimRight(zd.local_zone, ".") + ":" + strings.TrimRight(zd.ipref_zone, ".")
}

func (ip IP32) String() string {
	addr := []byte{0, 0, 0, 0}
	be.PutUint32(addr, uint32(ip))
	return net.IP(addr).String()
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
