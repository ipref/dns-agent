/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"encoding/binary"
	"github.com/ipref/ref"
	"log"
	"net"
)

/* Broker operations

The broker consolidates data from different DNS servers to a single set per
each combination of local domain and ipref domain. It requires quorum among
servers to declare data valid before sending to the mapper.
*/

const (

	// state codes

	NEW = iota
	SENT
	ACKED
)

type M32 int32 // mark, stamp/counter provided by the mapper
type O32 int32 // id associated with source, provided by the mapper

type IP32 uint32 // ip address

func (ip IP32) String() string {
	addr := []byte{0, 0, 0, 0}
	be.PutUint32(addr, uint32(ip))
	return net.IP(addr).String()
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
	Host
	state  int
	batch  int  // batch id to match acks
	remove bool // remove item from DNS records
}

type MapData struct {
	source string
	hash   uint64               // current hash
	hstat  map[IprefAddr]Status // host status
}

type StateData struct {
	source string
	hash   uint64
	hosts  map[IprefAddr]Host
}

type SrvData struct {
	server string
	hash   uint64
	hosts  map[IprefAddr]Host
}

type AggData struct { // data from all servers for a source
	source    string
	quorum    int
	hash_sent uint64
	srvdata   map[string]SrvData
}

type DnsData struct { // data from a single server
	source string
	server string
	hash   uint64
	hosts  map[IprefAddr]Host
}

var be = binary.BigEndian

var sources map[string][]string // source -> [server1:port, server2:port, ...]
var aggdata map[string]AggData  // source -> aggdata -> srvdata
var mapdata map[string]MapData  // source -> host status

//var mstat map[string]*MapStatus
var dnsdataq chan DnsData
var statedataq chan StateData
var mreqq chan (*MreqData)

func new_state(sd StateData) {

	md, ok := mapdata[sd.source]
	if !ok {
		md.source = sd.source
		md.hstat = make(map[IprefAddr]Status)
		mapdata[sd.source] = md
	}

	if sd.hash == md.hash {
		return // nothing new
	}

	// update map

	for _, hs := range md.hstat {
		hs.remove = true
	}

	for iraddr, host := range sd.hosts {
		hs, ok := md.hstat[iraddr]
		if !ok || hs.ip != host.ip || hs.name != host.name {
			hs.ip = host.ip
			hs.name = host.name
			hs.state = NEW
		}
		hs.remove = false
	}

	md.hash = sd.hash
}

func new_data(data DnsData) {

	// save data

	agg, ok := aggdata[data.source]
	if !ok {
		agg.source = data.source
		agg.quorum = len(sources[data.source])/2 + 1
		agg.srvdata = make(map[string]SrvData)
	}

	srv, ok := agg.srvdata[data.server]
	if !ok {
		srv.server = data.server
	}

	srv.hash = data.hash
	srv.hosts = data.hosts

	agg.srvdata[data.server] = srv

	// check if we have a quorum (number of servers with the same hash)

	qcount := make(map[uint64]int)

	for _, srv := range agg.srvdata {

		count := qcount[srv.hash]
		count++
		qcount[srv.hash] = count

		if count == agg.quorum {
			if srv.hash != agg.hash_sent {
				// new data reached quorum
				agg.hash_sent = srv.hash
				statedataq <- StateData{data.source, srv.hash, srv.hosts}
			}
			break
		}
	}
}

func new_mapper_request(mreq *MreqData) {

	switch mreq.cmd {
	case GET_CURRENT:
		/*
			// Send info about current sources

			for _, stat := range mstat {

				if len(stat.current.source) > 0 {

					req := new(MreqData)
					req.cmd = SEND_CURRENT
					req.data = MreqSendCurrent{
						len(stat.current.arecs),
						stat.current.hash,
						stat.current.source,
					}

					mclientq <- req
				}
			}
		*/
	case GET_RECORDS:
		/*
			// Send records mapper

			data := mreq.data.(MreqGetRecords)
			stat, ok := mstat[data.source]

			if !ok || stat.current.source != data.source || stat.current.hash != data.hash {
				log.Printf("ERR:        no records for: %v, ignoring", data.source)
				break
			}

			req := new(MreqData)
			req.cmd = SEND_RECORDS
			req.data = MreqSendRecords{
				data.oid,
				data.mark,
				stat.current.hash,
				stat.current.source,
				stat.current.arecs,
			}

			mclientq <- req
		*/
	default:
		log.Printf("ERR:        unknown mapper request code: %v, ignoring", mreq.cmd)
	}
}

func broker() {

	for {
		select {
		case data := <-dnsdataq:
			new_data(data)
		case state := <-statedataq:
			new_state(state)
		case mreq := <-mreqq:
			new_mapper_request(mreq)
		}
	}
}
