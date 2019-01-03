/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"github.com/ipref/ref"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

type MapperConn struct {
	conn  *net.UnixConn
	msgid byte
}

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

	mcon := MapperConn{msgid: byte(rand.Intn(256))}

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

					// look for TXT containing AA

					hdr := rr.Header()

					if hdr.Rrtype != dns.TypeTXT || hdr.Class != dns.ClassINET {
						continue
					}

					for _, txt := range rr.(*dns.TXT).Txt {

						// get IPREF address

						if !strings.HasPrefix(txt, "AA ") {
							continue
						}
						addr := strings.Split(txt[3:], "+")

						if len(addr) != 2 {
							log.Printf("ERR %v invalid IPREF address: %v\n", zone, toks[1])
							continue
						}

						addr[0] = strings.TrimSpace(addr[0])
						addr[1] = strings.TrimSpace(addr[1])

						// get reference

						ref, err := ref.Parse(addr[1])
						if err != nil {
							log.Printf("ERR %v invalid IPREF reference: %v %v\n", zone, addr[1], err)
							continue
						}

						// get gw, resolve if necessary

						gw := net.ParseIP(addr[0])

						if gw == nil {

							addrs, err := net.LookupHost(addr[0])
							if err != nil || len(addrs) == 0 {
								log.Printf("ERR %v cannot resolve IPREF address portion: %v\n", zone, err)
								continue
							}

							gw = net.ParseIP(addrs[0]) // use first address for now
							if gw == nil {
								log.Printf("ERR %v invalid IPREF address portion: %v\n", zone, addrs[0])
								continue
							}
						}

						gw = gw.To4()

						// send to mapper

						if cli.debug {
							if ref.H != 0 {
								log.Printf("%v sending to mapper: %v AA %v + %x-%016x\n", zone, hdr.Name, gw, ref.H, ref.L)
							} else {
								log.Printf("%v sending to mapper: %v AA %v + 0-%x\n", zone, hdr.Name, gw, ref.L)
							}
						}
						err = send_to_mapper(&mcon, hdr.Name, gw, ref)
						if err != nil {
							log.Printf("ERR %v send to mapper failed: %v\n", zone, err)
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
