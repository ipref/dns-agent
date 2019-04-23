/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

const (
	RECONNECT = 17 // [s] delay between reconnect
	MAXPKTLEN = 16384
	// mapper request codes
	GET_CURRENT  = 1
	SEND_CURRENT = 2
	GET_RECORDS  = 3
	SEND_RECORDS = 4
)

type MreqData struct {
	code 	int
	hash	int64
	source string
	oid		O32
	mark    M32
	arecs   []AddrRec
}

var mclnq chan(*MreqData)

func send_to_mapper(conn *net.UnixConn, connerr chan<- string, mreq *MreqData) {

	var msg [MAXPKTLEN]byte
	var wlen int

	_, err = conn.Write(msg[:wlen])
	if err != nil {
		// this will lead to re-connect and recreation of goroutines
		connerr <- fmt.Sprintf("write error: %v", err)
		return
	}

}

func read_from_mapper(conn *net.UnixConn, connerr chan<- string) {

	var msg [MAXPKTLEN]byte

	rlen, err := conn.Read(msg[:])
	if err != nil {
		// this will lead to re-connect and recreation of goroutines
		connerr <- fmt.Sprintf("read error: %v", err)
		return
	}

}

func mclient_read(conn *net.UnixConn, connerr chan<- string, quit <-chan int) {

	log.Printf("mclient read starting")

	for {
		select {
		case <- quit:
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
		case <- quit:
			log.Printf("mclient write quitting")
			return
		case mreq := <-mclientq:
			send_to_mapper(conn, connerr, mreq)
		}
	}
}

// Start new mclient. In case of reconnect, the old client will quit and
// disappear along with old conn and channels.
func mclient_conn() {

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

			errmsg := <- connerr
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
