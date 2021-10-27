/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"encoding/binary"
	"github.com/ipref/ref"
	"log"
	"net"
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
	ACK
	EXPIRE
	RESEND
)

const (
	DLY_SEND   = 257 * time.Millisecond
	DLY_EXPIRE = 293 * time.Second
)

type IP32 uint32 // ip address

func (ip IP32) String() string {
	addr := []byte{0, 0, 0, 0}
	be.PutUint32(addr, uint32(ip))
	return net.IP(addr).String()
}

type HostReq struct {
	source string
	req    int
	batch  uint32
}

type IprefAddr struct {
	gw  IP32
	ref ref.Ref
}

type Host struct {
	ip   IP32
	name string
}

type Status struct {
	state int
	batch uint32 // batch id to match acks
}

type HostData struct {
	source  string
	qrmhash uint64 // quorum hash
	allsent bool   // all data sent to mapper
	hosts   map[IprefAddr]Host
	stat    map[IprefAddr]Status
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
	hosts  map[IprefAddr]Host
}

var be = binary.BigEndian

var sources map[string][]string  // source -> [server1:port, server2:port, ...]
var aggdata map[string]AggData   // source -> aggdata -> srvdata
var hostdata map[string]HostData // source -> host data/status

var srvdataq chan SrvData
var qrmdataq chan SrvData
var hostreqq chan HostReq

// make a host request

func hostreq(source string, req int, batch uint32, dly time.Duration) {

	go func(source string, req int, batch uint32, dly time.Duration) {
		time.Sleep(dly)
		hostreqq <- HostReq{source, req, batch}
	}(source, req, batch, dly)
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

	if space < V1_AREC_LEN {
		log.Printf("E cannot send host data to mapper: packet size too small")
	}

	if cli.debug {
		log.Printf("scanning for records to send  %v  hash[%016x]  batch[%08x]",
			hdata.source, sreq.qrmhash, sreq.batch)
	}

	for iraddr, hs := range hdata.stat {

		host := hdata.hosts[iraddr]

		if cli.debug {
			statestr := "UNK"
			switch hs.state {
			case NEW:
				statestr = "NEW"
			case ACKED:
				statestr = "ACKED"
			case SENT:
				statestr = "SENT"
			}
			log.Printf("|   %-5v   %-12v  AA  %-16v + %v  =>  %v",
				statestr, host.name, iraddr.gw, &iraddr.ref, host.ip)
		}

		if hs.state == NEW {

			hs.state = SENT
			hs.batch = sreq.batch

			hdata.stat[iraddr] = hs

			sreq.recs = append(sreq.recs, AddrRec{host.ip, iraddr.gw, iraddr.ref})

			if space -= V1_AREC_LEN; space < V1_AREC_LEN {
				break
			}
		}
	}

	if len(sreq.recs) > 0 {

		sendreqq <- sreq
		hostreq(source, SEND, 0, DLY_SEND)
		hostreq(sreq.source, EXPIRE, sreq.batch, DLY_EXPIRE)

	} else {

		hdata.allsent = true
		hostdata[source] = hdata
	}
}

func ack_hosts(source string, batch uint32) {

	hdata, ok := hostdata[source]

	log.Printf("I ACK records:  %v  hash[%016x]  batch[%08x]", source, hdata.qrmhash, batch)

	if ok {
		for iraddr, hs := range hdata.stat {
			if hs.batch == batch && hs.state == SENT {
				hs.state = ACKED
				hdata.stat[iraddr] = hs
			}
		}
	}
}

// sent and ack should have come by now, re-send if not
func expire_host_acks(source string, batch uint32) {

	hdata, ok := hostdata[source]

	resend := false

	if ok {
		for iraddr, hs := range hdata.stat {
			if hs.batch == batch && hs.state == SENT {
				hs.state = NEW
				hdata.stat[iraddr] = hs
				resend = true
			}
		}
	}

	if resend {
		log.Printf("W unacknowledged:  %v  hash[%016x]  batch[%08x], resending", source, hdata.qrmhash, batch)
		hostreq(source, SEND, 0, DLY_SEND)
	}
}

func resend_host_data(source string) {

	hdata, ok := hostdata[source]

	log.Printf("I RESEND request:  %v, resending", source)

	if ok {
		for iraddr, hs := range hdata.stat {
			hs.state = NEW
			hs.batch = 0
			hdata.stat[iraddr] = hs
		}
	}

	hdata.allsent = false
	hostdata[source] = hdata

	hostreq(source, SEND, 0, DLY_SEND)
}

// new quorum data coming from aggregation
func new_qrmdata(qdata SrvData) {

	log.Printf("I new quorum:  %v  hash(%v)[%016x]", qdata.source, len(qdata.hosts), qdata.hash)

	//if cli.debug {
	//	for iraddr, host := range qdata.hosts {
	//		log.Printf("|   %-12v  AA  %-16v + %v  =>  %v\n", host.name, iraddr.gw, &iraddr.ref, host.ip)
	//	}
	//}

	var hdata HostData

	hdata.source = qdata.source
	hdata.qrmhash = qdata.hash
	hdata.allsent = false
	hdata.hosts = qdata.hosts
	hdata.stat = make(map[IprefAddr]Status)

	// add host status

	for iraddr, _ := range qdata.hosts {

		hdata.stat[iraddr] = Status{NEW, 0}
	}

	hostdata[qdata.source] = hdata

	hostreq(hdata.source, SEND, 0, DLY_SEND)
}

// new server data coming from pollers
func new_srvdata(data SrvData) {

	// save server data

	agg, ok := aggdata[data.source]

	if !ok {
		agg.source = data.source
		agg.quorum = len(sources[data.source])/2 + 1
		agg.srvdata = make(map[string]SrvData)
		aggdata[data.source] = agg

		log.Printf("I source  %v  quorum %v out of %v:", agg.source, agg.quorum, len(sources[data.source]))
		for _, server := range sources[data.source] {
			log.Printf("|   %v", server)
		}
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
				if cli.debug {
					log.Printf("hostreqq:  %v  SEND records to mapper", req.source)
				}
				send_host_data(req.source)
			case ACK:
				if cli.debug {
					log.Printf("hostreqq:  %v  ACK batch[%08x] from mapper", req.source, req.batch)
				}
				ack_hosts(req.source, req.batch)
			case EXPIRE:
				if cli.debug {
					log.Printf("hostreqq:  %v  EXPIRE batch[%08x] from timer", req.source, req.batch)
				}
				expire_host_acks(req.source, req.batch)
			case RESEND:
				if cli.debug {
					log.Printf("hostreqq:  %v  RESEND records to mapper", req.source)
				}
				resend_host_data(req.source)
			case NULL:
				if cli.debug {
					log.Printf("hostreqq:  NULL")
				}
			}
		}
	}
}
