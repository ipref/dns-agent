/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"crypto/md5"
	"fmt"
	"github.com/ipref/ref"
	"github.com/miekg/dns"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

type IprefAddr struct {
	gw  IP32
	ref ref.Ref
}

func send_to_broker(mapping, local_zone, ipref_zone string, dedup map[IprefAddr]IP32) {

	buf := make([]byte, 8, 8)
	hash := md5.New()

	zdata := new(ZoneData)
	zdata.local_zone = local_zone
	zdata.ipref_zone = ipref_zone

	for ipref_addr, ip := range dedup {

		arec := AddrRec{0, ip, ipref_addr.gw, ipref_addr.ref}
		zdata.arecs = append(zdata.arecs, arec)

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

	zdata.hash = hash.Sum(nil)

	if cli.debug { // pretty print results

		var sb strings.Builder

		fmt.Fprintf(&sb, "%v  num records: %v  hash: 02x\n", mapping, zdata.hash)
		for _, arec := range zdata.arecs {
			fmt.Fprintf(&sb, "    %v  =  %v + %v", arec.ip, arec.gw, arec.ref)
		}
		log.Printf(sb.String())
	}
}

func poll_a_zone(mapping string) {

	// LOCAL:ZONE:SERVER[:PORT]

	toks := strings.Split(mapping, ":")

	if len(toks) < 3 || len(toks) > 4 {
		log.Printf("ERR invalid zone mapping: %v", mapping)
		return
	}

	local_zone := toks[0]
	ipref_zone := toks[1]

	if len(local_zone) == 0 || len(ipref_zone) == 0 {
		log.Printf("ERR missing zone name: %v", mapping)
		return
	}

	if local_zone[len(local_zone)-1:] != "." {
		local_zone += "."
	}

	if ipref_zone[len(ipref_zone)-1:] != "." {
		ipref_zone += "."
	}

	if len(toks) < 4 {
		toks = append(toks, "53")
	}
	zsrv := strings.Join(toks[2:], ":")

	// initial delay

	dly := time.Duration(rand.Intn(initial_delay)) * time.Second
	log.Printf("%v initial delay: %v\n", mapping, dly)
	time.Sleep(dly)

	// poll loop

	for {

		dedup := make(map[IprefAddr]IP32)

		t := new(dns.Transfer)
		m := new(dns.Msg)
		m.SetAxfr(ipref_zone)
		c, err := t.In(m, zsrv)
		if err != nil {
			log.Printf("ERR %v transfer failed: %v\n", mapping, err)
		} else {
			for e := range c {
				if e.Error != nil && cli.debug {
					log.Printf("ERR %v envelope error: %v\n", mapping, e.Error)
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
							log.Printf("ERR %v invalid IPREF address: %v\n", mapping, toks[1])
							continue
						}

						addr[0] = strings.TrimSpace(addr[0])
						addr[1] = strings.TrimSpace(addr[1])

						// get reference

						ref, err := ref.Parse(addr[1])
						if err != nil {
							log.Printf("ERR %v invalid IPREF reference: %v %v\n", mapping, addr[1], err)
							continue
						}

						// get gw, resolve if necessary

						gw := net.ParseIP(addr[0])

						if gw == nil {

							addrs, err := net.LookupHost(addr[0])
							if err != nil || len(addrs) == 0 {
								log.Printf("ERR %v cannot resolve IPREF address portion: %v\n", mapping, err)
								continue
							}

							gw = net.ParseIP(addrs[0]) // use first address for now
							if gw == nil {
								log.Printf("ERR %v invalid IPREF address portion: %v\n", mapping, addrs[0])
								continue
							}
						}

						gw = gw.To4()

						// find ip

						lhost := hdr.Name + "." + local_zone
						laddrs, err := net.LookupHost(lhost)
						if err != nil || len(laddrs) == 0 {
							log.Printf("ERR %v cannot resolve IP of local host: %v\n", mapping, lhost)
							continue
						}

						ip := net.ParseIP(laddrs[0]) // user first address for now
						if ip == nil {
							log.Printf("ERR %v invalid local host IP address: %v\n", mapping, laddrs[0])
						}

						// save unique

						ipref_addr := IprefAddr{IP32(be.Uint32(gw)), ref}

						_, ok := dedup[ipref_addr]
						if ok {
							log.Printf("%v duplicate ipref mapping: %v = %v + %v, discarding", mapping, ip, gw, ref)
						} else {
							dedup[ipref_addr] = IP32(be.Uint32(ip))
						}
					}
				}
			}
		}

		send_to_broker(mapping, local_zone, ipref_zone, dedup)

		// random delay

		ivl := cli.poll_ivl * 60 * (100 - interval_fuzz)
		ivl += rand.Intn(cli.poll_ivl*60*interval_fuzz) * 2
		ivl /= 100
		dly = time.Duration(ivl) * time.Second
		if cli.debug {
			log.Printf("%v poll delay: %v\n", mapping, dly)
		}
		time.Sleep(dly)
	}
}
