/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"encoding/binary"
	. "github.com/ipref/common"
	"log"
	"math/rand"
	"time"
)

/* Broker operations

The broker consolidates data from different DNS servers to a single set per
each combination of local domain and ipref domain. It requires quorum among
servers to declare data valid before sending to the mapper.
*/

const ( // state codes

	NEW = iota
	SENT
	ACKED
)

const ( // host request codes

	NULL = iota
	SEND
	SEND_HASH
	ACK
	ACK_HASH
	NACK_HASH
	EXPIRE
)

const (
	DLY_SEND   = 257 * time.Millisecond
	DLY_EXPIRE = 5 * time.Second
)

type HostReq struct {
	req     int
	source  string
	batch   uint32 // holds count for HOST_DATA_HASH
	qrmhash uint64
}

type Host struct {
	ip   IP
	name string
}

type Status struct {
	state int
	batch uint32 // batch id to match acks
}

type HostData struct {
	source  string
	qrmhash uint64 // quorum hash
	hosts   map[IpRef]Host
	stat    map[IpRef]Status
}

type AggData struct { // data from all servers for a source
	source  string
	quorum  int
	qrmhash uint64 // hash of servers that reached quorum
	srvdata map[string]SrvData
}

type SrvData struct { // data from a single server
	source string
	server string
	hash   uint64
	hosts  map[IpRef]Host
}

var be = binary.BigEndian

var sources map[string][]string  // source -> [server1:port, server2:port, ...]
var aggdata map[string]AggData   // source -> aggdata -> srvdata
var hostdata map[string]HostData // source -> host data/status

var srvdataq chan SrvData
var qrmdataq chan SrvData
var hostreqq chan HostReq

// make a host request
func hostreq(req int, source string, batch uint32, qrmhash uint64, dly time.Duration) {

	hreq := HostReq{req, source, batch, qrmhash}

	go func(req HostReq, dly time.Duration) {
		time.Sleep(dly)
		hostreqq <- req
	}(hreq, dly)
}

func send_hash(source string) {

	// send hash to mapper slightly more frequently than the poll time

	dly := time.Duration((cli.poll_ivl*90)/100+rand.Intn((cli.poll_ivl*10)/100)) * time.Second
	hostreq(SEND_HASH, source, 0, 0, dly)

	// send hash only if all sent and acknowledged

	hdata, ok := hostdata[source]

	if !ok {
		return
	}

	for _, hs := range hdata.stat {

		if hs.state != ACKED {
			return
		}
	}

	var sreq SendReq

	sreq.cmd = V1_REQ | V1_MC_HOST_DATA_HASH
	sreq.source = source
	sreq.qrmhash = hdata.qrmhash
	sreq.batch = uint32(len(hdata.hosts))
	sreq.recs = nil

	sendreqq <- sreq
}

func nack_hash(source string, count uint32, qrmhash uint64) {

	hdata, ok := hostdata[source]

	log.Printf("I NACK HASH:  %v  hash(%v)[%016x], resending", source, count, qrmhash)

	if ok {
		for iraddr, hs := range hdata.stat {
			hs.state = NEW
			hs.batch = 0
			hdata.stat[iraddr] = hs
		}
	}

	hostreq(SEND, source, 0, 0, DLY_SEND)
}

func send_host_data(source string) {

	hdata, ok := hostdata[source]

	if !ok {
		log.Printf("E unexpected empty host data for  %v", source)
		return
	}

	var sreq SendReq

	sreq.cmd = V1_REQ | V1_MC_HOST_DATA
	sreq.source = source
	sreq.qrmhash = hdata.qrmhash
	sreq.batch = new_batchid()
	sreq.recs = make([]AddrRec, 0)

	space := MAXPKTLEN
	if cli.devmode {
		space = 200
	}
	space -= V1_HDR_LEN
	space -= 4                     // batch id
	space -= 8                     // hash
	space -= len(sreq.source) + 10 // source string plus possible padding

	if space < V1_AREC_MAX_LEN {
		log.Printf("E cannot send host data to mapper: packet size too small")
	}

	if cli.debug {
		log.Printf("scanning for records to send  %v  hash[%016x]  batch[%08x]",
			hdata.source, sreq.qrmhash, sreq.batch)
	}

	for iraddr, hs := range hdata.stat {

		host := hdata.hosts[iraddr]

		if hs.state == NEW {

			hs.state = SENT
			hs.batch = sreq.batch

			hdata.stat[iraddr] = hs

			arec := AddrRec{IPZero(host.ip.Len()), host.ip, iraddr.IP, iraddr.Ref}
			sreq.recs = append(sreq.recs, arec)

			if space -= arec.EncodedLen(); space < arec.EncodedLen() {
				break
			}
		}
	}

	if len(sreq.recs) > 0 {

		sendreqq <- sreq
		hostreq(SEND, source, 0, 0, DLY_SEND)
		hostreq(EXPIRE, sreq.source, sreq.batch, sreq.qrmhash, DLY_EXPIRE)

	}
}

func ack_hosts(source string, qrmhash uint64, batch uint32) {

	hdata, ok := hostdata[source]

	if ok && hdata.qrmhash == qrmhash {

		count := 0

		for iraddr, hs := range hdata.stat {
			if hs.batch == batch && hs.state == SENT {
				hs.state = ACKED
				hdata.stat[iraddr] = hs
				count++
			}
		}

		log.Printf("I ACK records(%v):  %v  hash[%016x]  batch[%08x]",
			count, source, qrmhash, batch)
	}

}

// sent and ack should have come by now, re-send if not
func expire_host_acks(source string, qrmhash uint64, batch uint32) {

	hdata, ok := hostdata[source]

	if ok && hdata.qrmhash == qrmhash {

		resend := false

		for iraddr, hs := range hdata.stat {
			if hs.batch == batch && hs.state == SENT {
				hs.state = NEW
				hdata.stat[iraddr] = hs
				resend = true
			}
		}

		if resend {
			log.Printf("W unacknowledged:  %v  hash[%016x]  batch[%08x], resending",
				source, hdata.qrmhash, batch)
			hostreq(SEND, source, 0, 0, DLY_SEND)
		}
	}
}

// new quorum data coming from aggregation
func new_qrmdata(qdata SrvData) {

	log.Printf("I new quorum:  %v  hash(%v)[%016x]", qdata.source, len(qdata.hosts), qdata.hash)

	var hdata HostData

	hdata.source = qdata.source
	hdata.qrmhash = qdata.hash
	hdata.hosts = qdata.hosts
	hdata.stat = make(map[IpRef]Status)

	// add host status

	for iraddr, _ := range qdata.hosts {

		hdata.stat[iraddr] = Status{NEW, 0}
	}

	hostdata[qdata.source] = hdata

	hostreq(SEND, qdata.source, 0, 0, DLY_SEND)
}

// new server data coming from pollers
func new_srvdata(data SrvData) {

	// save server data

	agg, ok := aggdata[data.source]

	if !ok {
		agg.source = data.source
		agg.quorum = len(sources[data.source])/2 + 1
		agg.qrmhash = data.hash ^ 1 // guarantee mismatch with server hash
		agg.srvdata = make(map[string]SrvData)
		aggdata[data.source] = agg

		log.Printf("I source  %v  quorum %v out of %v:", agg.source, agg.quorum, len(sources[data.source]))
		for _, server := range sources[data.source] {
			log.Printf(":   %v", server)
		}

		hostreq(SEND_HASH, agg.source, 0, 0, DLY_SEND)
	}

	agg.srvdata[data.server] = data

	// check if we have a quorum (number of servers with the same hash)

	qcount := make(map[uint64]int)

	for _, srv := range agg.srvdata {

		count := qcount[srv.hash]
		count++
		qcount[srv.hash] = count

		if count == agg.quorum {
			if srv.hash != agg.qrmhash {
				// new server data reached quorum
				agg.qrmhash = srv.hash
				aggdata[data.source] = agg
				qrmdataq <- srv
			}
			break
		}
	}
}

func broker() {

	for {
		select {
		case data := <-srvdataq:
			new_srvdata(data)
		case qdata := <-qrmdataq:
			new_qrmdata(qdata)
		case req := <-hostreqq:
			switch req.req {
			case SEND:
				send_host_data(req.source)
			case ACK:
				ack_hosts(req.source, req.qrmhash, req.batch)
			case EXPIRE:
				expire_host_acks(req.source, req.qrmhash, req.batch)
			case SEND_HASH:
				send_hash(req.source)
			case ACK_HASH:
				log.Printf("I ACK HASH:  %v  hash(%v)[%016x]",
					req.source, req.batch, req.qrmhash)
			case NACK_HASH:
				nack_hash(req.source, req.batch, req.qrmhash)
			case NULL:
				if cli.debug {
					log.Printf("hostreqq:  NULL")
				}
			}
		}
	}
}
