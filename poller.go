/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	. "github.com/ipref/common"
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

type ByIpRef []IpRef

func (arr ByIpRef) Len() int {
	return len(arr)
}

func (arr ByIpRef) Less(i, j int) bool {

	if arr[i].IP.Compare(arr[j].IP) < 0 {
		return true
	}
	if arr[i].IP.Compare(arr[j].IP) > 0 {
		return false
	}
	if arr[i].Ref.H < arr[j].Ref.H {
		return true
	}
	if arr[i].Ref.H > arr[j].Ref.H {
		return false
	}
	return arr[i].Ref.L < arr[j].Ref.L
}

func (arr ByIpRef) Swap(i, j int) {
	arr[i], arr[j] = arr[j], arr[i]
}

func send_to_broker(source, server string, hosts map[IpRef]Host) {

	var data SrvData

	data.source = source
	data.server = server

	buf := make([]byte, 8, 8)
	hash := fnv.New64a()

	keys := make([]IpRef, 0, len(hosts))
	for key := range hosts {
		keys = append(keys, key)
	}

	sort.Sort(ByIpRef(keys)) // sort keys to make hash meaningful

	for _, iraddr := range keys {

		host := hosts[iraddr]

		hash.Write(host.ip.AsSlice())
		hash.Write(iraddr.IP.AsSlice())
		be.PutUint64(buf, iraddr.Ref.H)
		hash.Write(buf)
		be.PutUint64(buf, iraddr.Ref.L)
		hash.Write(buf)
	}

	data.hash = hash.Sum64()
	data.hosts = hosts

	if cli.debug {

		log.Printf("server records:  %v at %v  hash(%v)[%016x]:\n", data.source, data.server, len(hosts), data.hash)
		for iraddr, host := range data.hosts {
			log.Printf(":   %-12v  AA  %-16v + %v  =>  %v\n", host.name, iraddr.IP, &iraddr.Ref, host.ip)
		}
	}

	srvdataq <- data
}

func poll_a_source(source, server string, dly time.Duration, fuzz int) {

	// LOCAL:PUBLIC SERVER:PORT

	toks := strings.Split(source, ":")

	local_domain := toks[0] + "."
	ipref_domain := toks[1] + "."

poll_loop:

	for {

		// random delay

		if cli.debug {
			log.Printf("poll delay: %v at %v %v\n", source, server, dly)
		}
		time.Sleep(dly)

		dly = time.Duration(cli.poll_ivl-fuzz+rand.Intn(fuzz*2)) * time.Second

		// get domain data

		hosts := make(map[IpRef]Host)

		t := new(dns.Transfer)
		m := new(dns.Msg)
		m.SetAxfr(ipref_domain)
		c, err := t.In(m, server)

		if err != nil {
			log.Printf("E %v at %v transfer failed: %v", source, server, err)
			continue
		}

		for e := range c {

			if e.Error != nil {

				errmsg := e.Error.Error()

				if errmsg != "dns: no SOA" {
					log.Printf("E %v at %v envelope error: %v", source, server, errmsg)
					continue poll_loop
				}

				if cli.debug {
					log.Printf("W %v at %v envelope: %v", source, server, errmsg)
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
						log.Printf("E %v at %v invalid IPREF address: %v, discarding", source, server, txt[3:])
						continue
					}

					addr[0] = strings.TrimSpace(addr[0])
					addr[1] = strings.TrimSpace(addr[1])

					// get reference

					ref, err := ref.Parse(addr[1])
					if err != nil {
						log.Printf("E %v at %v invalid IPREF reference: %v %v, discarding", source, server, addr[1], err)
						continue
					}

					// get gw, resolve if necessary

					gw, err := ParseIP(addr[0])
					if err == nil {
						if gw.Ver() != cli.gw_ipver {
							continue
						}
					} else {
						addrs, err := net.LookupHost(addr[0])
						if err != nil || len(addrs) == 0 {
							log.Printf("W %v at %v cannot resolve IPREF address portion: %v, discarding", source, server, err)
							continue
						}

						for _, addr := range addrs {
							gw, err = ParseIP(addr)
							if err == nil && gw.Ver() == cli.gw_ipver {
								goto have_gw
							}
						}
						log.Printf("W %v at %v invalid IPREF address portion: %v, discarding", source, server, addrs[0])
						continue
					have_gw:
					}

					// find ip

					hostname := strings.Split(hdr.Name, ".")[0]
					lhost := hostname + "." + local_domain
					laddrs, err := net.LookupHost(lhost)
					if err != nil || len(laddrs) == 0 {
						log.Printf("W %v at %v cannot resolve IP address of local host: %v, discarding", source, server, lhost)
						continue
					}

					var ip IP
					for _, addr := range laddrs {
						ip, err = ParseIP(addr)
						if err == nil && ip.Ver() == cli.ea_ipver {
							goto have_ip
						}
					}
					log.Printf("W %v at %v invalid local host IP address: %v, discarding", source, server, laddrs[0])
					continue
				have_ip:

					// save dns record

					iraddr := IpRef{gw, ref}

					_, ok := hosts[iraddr]
					if ok {
						log.Printf("W %v at %v duplicate ipref address:  %v  AA  %v + %v", source, server, hostname, gw, ref)
					} else {
						hosts[iraddr] = Host{ip, hostname}
					}
				}
			}
		}

		send_to_broker(source, server, hosts)
	}
}
