/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"bytes"
	"log"
)

/* Broker operations

The broker counts the number of consecutive data signaled from each ipref
zone. If the count reaches designated value (typically 2), it sends the data
to the mapper unless the same data has already been sent.

The broker requests time marks from mapper on regular basis. This is used to
age sent data. After the time mark reaches designated value (typically half
of mapper's data record time out), it resends the data to the mapper.

*/

const (
	ZDQLEN       = 2
	ACCEPT_COUNT = 2
)

type ZoneStatus struct {
	//
	send struct {
		data   *ZoneData
		id     uint16
		status int
		mark   M32
	}

	last struct {
		data  *ZoneData
		count int
	}
}

var zdq chan (*ZoneData)

func new_zone_data(statmap map[string]*ZoneStatus, newdata *ZoneData) {

	stat, ok := statmap[newdata.ipref_zone]

	// initialize zone status

	if !ok {
		log.Printf("%v:%v new zone", newdata.local_zone, newdata.ipref_zone)
		stat = new(ZoneStatus)
		statmap[newdata.ipref_zone] = stat
		stat.send.data = new(ZoneData)
		stat.last.data = new(ZoneData)
	}

	// determine if zone data is new

	if !bytes.Equal(stat.last.data.hash, newdata.hash) {
		log.Printf("%v:%v %02x: new data", newdata.local_zone, newdata.ipref_zone, newdata.hash)
		stat.last.data = newdata
		stat.last.count = 0
	}

	if bytes.Equal(stat.send.data.hash, stat.last.data.hash) {
		if cli.debug {
			log.Printf("%v:%v %02x: already sent", stat.last.data.local_zone,
				stat.last.data.ipref_zone, stat.last.data.hash)
		}
		return // already sent
	}

	stat.last.count += 1

	if stat.last.count < ACCEPT_COUNT {
		if cli.debug {
			log.Printf("%v:%v %02x: count(%v)", stat.last.data.local_zone,
				stat.last.data.ipref_zone, stat.last.data.hash, stat.last.count)
		}
		return // didn't reach accept count
	}

	// send new data to mapper

	log.Printf("%v:%v %02x: count(%v) sending to mapper", stat.last.data.local_zone,
		stat.last.data.ipref_zone, stat.last.data.hash, stat.last.count)

	stat.send.data = stat.last.data
}

func broker() {

	statmap := make(map[string]*ZoneStatus)

	for {

		select {
		case newdata := <-zdq:
			new_zone_data(statmap, newdata)
		}
	}
}
