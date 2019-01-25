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

func send_to_broker(mapping, local_zone, ipref_zone string, dedup map[IprefAddr]IP32) {

	buf := make([]byte, 8, 8)
	hash := md5.New()

	zdata := new(ZoneData)
	zdata.local_zone = local_zone
	zdata.ipref_zone = ipref_zone

	keys := make([]IprefAddr, 0, len(dedup))
	for key := range dedup {
		keys = append(keys, key)
	}

	sort.Sort(ByIpRef(keys)) // sort keys to make hash meaningful

	for _, ipref_addr := range keys {

		ip := dedup[ipref_addr]

		arec := AddrRec{0, ip, ipref_addr.gw, ipref_addr.ref, ipref_addr.host}
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

		fmt.Fprintf(&sb, "%v  found(%v)  hash: %02x\n", mapping, len(zdata.arecs), zdata.hash)
		for _, arec := range zdata.arecs {
			fmt.Fprintf(&sb, "    %-12v  %-16v  =  %-16v +  %v\n", arec.host, arec.ip, arec.gw, &arec.ref)
		}
		log.Printf(sb.String())
	}

	zdq <- zdata
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

poll_loop:

	for {

		// random delay

		if cli.debug {
			log.Printf("%v poll delay: %v\n", mapping, dly)
		}
		time.Sleep(dly)

		ivl := cli.poll_ivl * 60 * (100 - interval_fuzz)
		ivl += rand.Intn(cli.poll_ivl*60*interval_fuzz) * 2
		ivl /= 100
		dly = time.Duration(ivl) * time.Second

		// get zone data

		dedup := make(map[IprefAddr]IP32)

		t := new(dns.Transfer)
		m := new(dns.Msg)
		m.SetAxfr(ipref_zone)
		c, err := t.In(m, zsrv)

		if err != nil {
			log.Printf("ERR %v transfer failed: %v", mapping, err)
			continue
		}

		for e := range c {

			if e.Error != nil {

				errmsg := e.Error.Error()

				if errmsg != "dns: no SOA" {
					log.Printf("ERR %v envelope error: %v", mapping, errmsg)
					continue poll_loop
				}

				if cli.debug {
					log.Printf("%v envelope: %v", mapping, errmsg)
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
						log.Printf("ERR %v invalid IPREF address: %v, discarding", mapping, toks[1])
						continue
					}

					addr[0] = strings.TrimSpace(addr[0])
					addr[1] = strings.TrimSpace(addr[1])

					// get reference

					ref, err := ref.Parse(addr[1])
					if err != nil {
						log.Printf("ERR %v invalid IPREF reference: %v %v, discarding", mapping, addr[1], err)
						continue
					}

					// get gw, resolve if necessary

					gw := net.ParseIP(addr[0])

					if gw == nil {

						addrs, err := net.LookupHost(addr[0])
						if err != nil || len(addrs) == 0 {
							log.Printf("ERR %v cannot resolve IPREF address portion: %v, discarding", mapping, err)
							continue
						}

						gw = net.ParseIP(addrs[0]) // use first address for now
						if gw == nil {
							log.Printf("ERR %v invalid IPREF address portion: %v, discarding", mapping, addrs[0])
							continue
						}
					}

					gw = gw.To4()

					// find ip

					host := strings.Split(hdr.Name, ".")[0]
					lhost := host + "." + local_zone
					laddrs, err := net.LookupHost(lhost)
					if err != nil || len(laddrs) == 0 {
						log.Printf("ERR %v cannot resolve IP address of local host: %v, discarding", mapping, lhost)
						continue
					}

					ip := net.ParseIP(laddrs[0]) // use first address for now
					if ip == nil {
						log.Printf("ERR %v invalid local host IP address: %v, discarding", mapping, laddrs[0])
						continue
					}

					// save unique

					ipref_addr := IprefAddr{IP32(be.Uint32(gw)), ref, host}

					_, ok := dedup[ipref_addr]
					if ok {
						log.Printf("%v duplicate ipref mapping: %v = %v + %v", mapping, ip, gw, ref)
					} else {
						dedup[ipref_addr] = IP32(be.Uint32(ip.To4()))
					}
				}
			}
		}

		send_to_broker(mapping, local_zone, ipref_zone, dedup)
	}
}
