/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"encoding/binary"
	"github.com/ipref/ref"
	"log"
	"net"
)

/* Broker operations

The broker consolidates data from different DNS servers to a single set per
each combination of local domain and ipref domain. It counts the number of
consecutive data signaled from servers. If the count reaches designated value,
typically 2, it marks the data as current. This is the data that is advertized
to the mapper.

*/

type M32 int32 // mark, stamp/counter provided by the mapper
type O32 int32 // id associated with source, provided by the mapper

type IP32 uint32 // ip address

func (ip IP32) String() string {
	addr := []byte{0, 0, 0, 0}
	be.PutUint32(addr, uint32(ip))
	return net.IP(addr).String()
}

type Host struct {
	ip   IP32
	name string
}

type IprefAddr struct {
	gw  IP32
	ref ref.Ref
}

//type MapStatus struct {
//	current *MapData
//	last    *MapData
//	count   int
//}

type StateData struct {
	source string
	hash   uint64
	hosts  map[IprefAddr]Host
}

type SrvData struct {
	hash  uint64
	hosts map[IprefAddr]Host
}

type AggData struct {
	quorum    int
	hash_sent uint64
	srvdata   map[string]SrvData
}

type DnsData struct {
	source string
	server string
	hash   uint64
	hosts  map[IprefAddr]Host
}

var be = binary.BigEndian

var sources map[string][]string // source -> [server1:port, server2:port, ...]
var aggdata map[string]AggData  // source -> aggdata -> srvdata

//var mstat map[string]*MapStatus
var dnsdataq chan DnsData
var statedataq chan StateData
var mreqq chan (*MreqData)

func new_data(data DnsData) {

	// save data

	agg, ok := aggdata[data.source]
	if !ok {
		agg.quorum = len(sources[data.source])/2 + 1
		agg.srvdata = make(map[string]SrvData)
	}

	sdata := agg.srvdata[data.server]

	sdata.hash = data.hash
	sdata.hosts = data.hosts

	agg.srvdata[data.server] = sdata

	// check if we have a quorum (number of servers with the same hash)

	qcount := make(map[uint64]int)

	for _, sdata := range agg.srvdata {

		count := qcount[sdata.hash]
		count++
		qcount[sdata.hash] = count

		if count == agg.quorum {
			if sdata.hash != agg.hash_sent {
				// new data reached quorum
				agg.hash_sent = sdata.hash
				statedataq <- StateData{data.source, sdata.hash, sdata.hosts}
			}
			break
		}
	}
}

func new_state(state StateData) {
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
