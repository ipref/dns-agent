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

	SEND = iota
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

type HostStatus struct {
	Host
	state  int
	batch  uint32 // batch id to match acks
	remove bool   // remove item from DNS records
}

type HostData struct {
	source  string
	qrmhash uint64 // current quorum hash
	hstat   map[IprefAddr]HostStatus
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
var hostdata map[string]HostData // source -> host status

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
		return
	}

	var sreq SendReq

	sreq.source = source
	sreq.batch = new_batchid()
	sreq.recs = make([]AddrRec, 0)

	space := MAXPKTLEN - V1_HDR_LEN
	space -= 4                     // batch id
	space -= len(sreq.source) + 10 // source string plus possible padding

	if space < V1_AREC_LEN {
		log.Printf("ERR  cannot send host data to mapper: packet size too small")
	}

	for iraddr, hs := range hdata.hstat {
		if hs.state == NEW {

			hs.state = SENT
			hs.batch = sreq.batch
			sreq.recs = append(sreq.recs, AddrRec{hs.ip, iraddr.gw, iraddr.ref})

			if space -= V1_AREC_LEN; space < V1_AREC_LEN {
				break
			}
		}
	}

	if len(sreq.recs) > 0 {

		sendreqq <- sreq
		hostreq(source, SEND, 0, DLY_SEND)
	}
}

func ack_hosts(source string, batch uint32) {

	hdata, ok := hostdata[source]

	if ok {
		for _, hs := range hdata.hstat {
			if hs.batch == batch && hs.state == SENT {
				hs.state = ACKED
			}
		}
	}
}

// sent but ack never came, so re-send them
func expire_host_acks(source string, batch uint32) {

	hdata, ok := hostdata[source]

	if ok {
		for _, hs := range hdata.hstat {
			if hs.batch == batch && hs.state == SENT {
				hs.state = NEW
			}
		}
	}

	hostreq(source, SEND, 0, DLY_SEND)
}

func resend_host_data(source string) {

	hdata, ok := hostdata[source]

	if ok {
		for _, hs := range hdata.hstat {
			hs.state = NEW
		}
	}

	hostreq(source, SEND, 0, DLY_SEND)
}

// new quorum data coming from aggregation
func new_qrmdata(qdata SrvData) {

	hdata, ok := hostdata[qdata.source]
	if !ok {
		hdata.source = qdata.source
		hdata.hstat = make(map[IprefAddr]HostStatus)
	}

	if hdata.qrmhash == qdata.hash {
		return // nothing new
	}

	if cli.debug {
		log.Printf("accepted quorum records(%v) from %s hash[%016x]", len(qdata.hosts), qdata.source, qdata.hash)
		for iraddr, host := range qdata.hosts {
			log.Printf("|   %-12v  AA  %-16v + %v  =>  %v\n", host.name, iraddr.gw, &iraddr.ref, host.ip)
		}
	}

	// update host data

	for _, hs := range hdata.hstat {
		hs.remove = true
	}

	for iraddr, host := range qdata.hosts {
		hs, ok := hdata.hstat[iraddr]
		if !ok || hs.ip != host.ip || hs.name != host.name {
			hs.ip = host.ip
			hs.name = host.name
			hs.batch = 0
			hs.state = NEW
		}
		hs.remove = false
	}

	hdata.qrmhash = qdata.hash

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
		if cli.debug {
			log.Printf("new aggregator:  %s  quorum(%v)", agg.source, agg.quorum)
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
					log.Printf("hostreqq:  %s  SEND records to mapper", req.source)
				}
				send_host_data(req.source)
			case ACK:
				if cli.debug {
					log.Printf("hostreqq:  %s  ACK batch[%08x] from mapper", req.batch, req.source)
				}
				ack_hosts(req.source, req.batch)
			case EXPIRE:
				if cli.debug {
					log.Printf("hostreqq:  %s  EXPIRE batch[%08x] from timer", req.batch, req.source)
				}
				expire_host_acks(req.source, req.batch)
			case RESEND:
				if cli.debug {
					log.Printf("hostreqq:  %s  RESEND records to mapper", req.source)
				}
				resend_host_data(req.source)
			}
		}
	}
}
