/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"strings"
	"time"
)

func poll_a_zone(zone string) {

	// zone name and server it's hosted on

	toks := strings.Split(zone, ":")

	if len(toks) < 2 || len(toks) > 3 {
		log.Printf("ERR invalid zone/server: %v", zone)
		return
	}

	zname := toks[0]

	if len(zname) == 0 {
		log.Printf("ERR missing zone name: %v", zone)
		return
	}

	if zname[len(zname)-1:] != "." {
		zname += "."
	}

	if len(toks) < 3 {
		toks = append(toks, "53")
	}
	zsrv := strings.Join(toks[1:], ":")

	// initial delay

	dly := time.Duration(rand.Intn(initial_delay)) * time.Second
	log.Printf("%v initial delay: %v\n", zone, dly)
	time.Sleep(dly)

	// poll loop

	for {

		t := new(dns.Transfer)
		m := new(dns.Msg)
		m.SetAxfr(zname)
		c, err := t.In(m, zsrv)
		if err != nil {
			log.Printf("ERR %v transfer failed: %v\n", zone, err)
		} else {
			for e := range c {
				if e.Error != nil && cli.debug {
					log.Printf("ERR %v envelope error: %v\n", zone, e.Error)
				}
				for _, rr := range e.RR {
					// only selected records
					rrtype := rr.Header().Rrtype
					if rrtype == dns.TypeTXT {
						if cli.debug {
							log.Printf("%v %v\n", zone, rr)
						}
					}
				}

			}
		}

		ivl := cli.poll_ivl * 60 * (100 - interval_fuzz)
		ivl += rand.Intn(cli.poll_ivl*60*interval_fuzz) * 2
		ivl /= 100
		dly = time.Duration(ivl) * time.Second
		if cli.debug {
			log.Printf("%v poll delay: %v\n", zone, dly)
		}
		time.Sleep(dly)
	}
}
