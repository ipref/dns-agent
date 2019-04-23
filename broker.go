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

type AddrRec struct {
	ea   IP32
	ip   IP32
	gw   IP32
	ref  ref.Ref
	host string
}

type MapData struct {
	local_domain string
	ipref_domain string
	source       string
	server       string
	quorum       int
	hash         uint64
	arecs        []AddrRec
}

type MapStatus struct {
	current *MapData
	last    *MapData
	count   int
}

var be = binary.BigEndian

var mstat map[string]*MapStatus
var mdataq chan (*MapData)
var mreqq chan (*MreqData)

func new_mdata(newdata *MapData) {

	stat, ok := mstat[newdata.source]

	// initialize map status

	if !ok {
		log.Printf("new source: %v quorum(%v)", newdata.source, newdata.quorum)
		stat = new(MapStatus)
		mstat[newdata.source] = stat
		stat.current = new(MapData)
		stat.last = new(MapData)
	}

	// determine if data is new

	if stat.last.hash != newdata.hash {
		if cli.debug {
			log.Printf("new data:   %v at %v %016x", newdata.source, newdata.server, newdata.hash)
		}
		stat.last = newdata
		stat.count = 0
	}

	if stat.current.hash == stat.last.hash {
		if cli.debug {
			log.Printf("same data:  %v at %v %016x", newdata.source, newdata.server, newdata.hash)
		}
		return // same as current
	}

	stat.count += 1

	if stat.count < newdata.quorum {
		log.Printf("count(%v):   %v at %v %016x", stat.count, newdata.source, newdata.server, newdata.hash)
		return // didn't reach quorum count
	}

	// new data reached quorum, tell mapper

	log.Printf("quorum(%v):  %v at %v %016x informing mapper", stat.count, newdata.source, newdata.server, newdata.hash)
	stat.current = stat.last
}

func new_mapper_request(mreq *MreqData) {

	switch mreq.code {
	case GET_CURRENT:

		// Send info about current sources

		for _, stat := range mstat {

			if len(stat.current.source) > 0 {

				req := MreqData {
					SEND_CURRENT
					stat.current.hash
					stat.current.source
				}

				mclnq <- &req
			}
		}

	case GET_RECORDS:

		// Send records mapper

		stat, ok := mstat[mreq.source]

		if !ok || stat.current.source != mreq.source || stat.current.hash != mreq.hash {
			log.Printf("ERR:        no records for: %v, ignoring", mreq.source)
			break
		}

		req := MreqData{
				SEND_RECORDS,
				stat.current.hash,
				stat.current.source,
				mreq.oid,
				mreq.mark,
				stat.current.arecs
			}

		mclnq <- &req

	default:
		log.Printf("ERR:        unknown mapper request code: %v, ignoring", mreq.code)
	}
}

func broker() {

	for {
		select {
		case mdata := <-mdataq:
			new_mdata(mdata)
		case mreq := <-mreqq:
			new_mapper_request(mreq)
		}
	}
}
