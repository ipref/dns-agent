/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"github.com/ipref/ref"
	"github.com/miekg/dns"
	"hash/fnv"
	"log"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"
)

type IprefAddr struct {
	gw   IP32
	ref  ref.Ref
	host string
}

type ByIpRef []IprefAddr

func (arr ByIpRef) Len() int {
	return len(arr)
}

func (arr ByIpRef) Less(i, j int) bool {

	if arr[i].gw < arr[j].gw {
		return true
	}
	if arr[i].gw > arr[j].gw {
		return false
	}
	if arr[i].ref.H < arr[j].ref.H {
		return true
	}
	if arr[i].ref.H > arr[j].ref.H {
		return false
	}
	return arr[i].ref.L < arr[j].ref.L
}

func (arr ByIpRef) Swap(i, j int) {
	arr[i], arr[j] = arr[j], arr[i]
}

func send_to_broker(source, server string, dedup map[IprefAddr]IP32) {

	var data DnsData

	data.source = source
	data.server = server

	buf := make([]byte, 8, 8)
	hash := fnv.New64a()

	keys := make([]IprefAddr, 0, len(dedup))
	for key := range dedup {
		keys = append(keys, key)
	}

	sort.Sort(ByIpRef(keys)) // sort keys to make hash meaningful

	for _, ipref_addr := range keys {

		ip := dedup[ipref_addr]

		arec := AddrRec{0, ip, ipref_addr.gw, ipref_addr.ref, ipref_addr.host}
		data.arecs = append(data.arecs, arec)

		be.PutUint32(buf[:4], uint32(arec.ea))
		hash.Write(buf[:4])
		be.PutUint32(buf[:4], uint32(arec.ip))
		hash.Write(buf[:4])
		be.PutUint32(buf[:4], uint32(arec.gw))
		hash.Write(buf[:4])
		be.PutUint64(buf, arec.ref.H)
		hash.Write(buf)
		be.PutUint64(buf, arec.ref.L)
		hash.Write(buf)
	}

	data.hash = hash.Sum64()

	if cli.debug {

		log.Printf("records:    %v at %v %016x total(%v):\n", data.source, data.server, data.hash, len(data.arecs))
		for _, arec := range data.arecs {
			log.Printf("|   %-12v  %-16v  =  %-16v +  %v\n", arec.host, arec.ip, arec.gw, &arec.ref)
		}
	}

	dnsdataq <- data
}

func poll_a_source(source, server string) {

	// LOCAL:PUBLIC SERVER:PORT

	toks := strings.Split(source, ":")

	local_domain := toks[0] + "."
	ipref_domain := toks[1] + "."

	// initial delay

	dly := time.Duration(rand.Intn(initial_delay)) * time.Second

poll_loop:

	for {

		// random delay

		if cli.debug {
			log.Printf("poll delay: %v at %v %v\n", source, server, dly)
		}
		time.Sleep(dly)

		ivl := cli.poll_ivl * 60 * (100 - interval_fuzz)
		ivl += rand.Intn(cli.poll_ivl*60*interval_fuzz) * 2
		ivl /= 100
		dly = time.Duration(ivl) * time.Second

		// get domain data

		dedup := make(map[IprefAddr]IP32)

		t := new(dns.Transfer)
		m := new(dns.Msg)
		m.SetAxfr(ipref_domain)
		c, err := t.In(m, server)

		if err != nil {
			log.Printf("ERR:        %v at %v transfer failed: %v", source, server, err)
			continue
		}

		for e := range c {

			if e.Error != nil {

				errmsg := e.Error.Error()

				if errmsg != "dns: no SOA" {
					log.Printf("ERR:        %v at %v envelope error: %v", source, server, errmsg)
					continue poll_loop
				}

				if cli.debug {
					log.Printf("WARN:       %v at %v envelope: %v", source, server, errmsg)
				}
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
						log.Printf("ERR:        %v at %v invalid IPREF address: %v, discarding", source, server, txt[3:])
						continue
					}

					addr[0] = strings.TrimSpace(addr[0])
					addr[1] = strings.TrimSpace(addr[1])

					// get reference

					ref, err := ref.Parse(addr[1])
					if err != nil {
						log.Printf("ERR:        %v at %v invalid IPREF reference: %v %v, discarding", source, server, addr[1], err)
						continue
					}

					// get gw, resolve if necessary

					gw := net.ParseIP(addr[0])

					if gw == nil {

						addrs, err := net.LookupHost(addr[0])
						if err != nil || len(addrs) == 0 {
							log.Printf("ERR:        %v at %v cannot resolve IPREF address portion: %v, discarding", source, server, err)
							continue
						}

						gw = net.ParseIP(addrs[0]) // use first address for now
						if gw == nil {
							log.Printf("ERR:        %v at %v invalid IPREF address portion: %v, discarding", source, server, addrs[0])
							continue
						}
					}

					gw = gw.To4()

					// find ip

					host := strings.Split(hdr.Name, ".")[0]
					lhost := host + "." + local_domain
					laddrs, err := net.LookupHost(lhost)
					if err != nil || len(laddrs) == 0 {
						log.Printf("ERR:        %v at %v cannot resolve IP address of local host: %v, discarding", source, server, lhost)
						continue
					}

					ip := net.ParseIP(laddrs[0]) // use first address for now
					if ip == nil {
						log.Printf("ERR:        %v at %v invalid local host IP address: %v, discarding", source, server, laddrs[0])
						continue
					}

					// save unique

					ipref_addr := IprefAddr{IP32(be.Uint32(gw)), ref, host}

					_, ok := dedup[ipref_addr]
					if ok {
						log.Printf("WARN:       %v at %v duplicate ipref mapping: %v = %v + %v", source, server, ip, gw, ref)
					} else {
						dedup[ipref_addr] = IP32(be.Uint32(ip.To4()))
					}
				}
			}
		}

		send_to_broker(source, server, dedup)
	}
}
