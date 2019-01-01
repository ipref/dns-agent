/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"fmt"
	"github.com/miekg/dns"
)

func main() {

	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr("wdmsys.com.")
	c, err := t.In(m, "192.168.84.7:53")
	if err != nil {
		fmt.Printf("transfer failed: %v\n", err)
	}
	for e := range c {
		if e.Error != nil {
			fmt.Printf("envelope error: %v\n", e.Error)
		} else {
			for _, r := range e.RR {
				// only CNAME and SOA
				rrtype := r.Header().Rrtype
				if rrtype == dns.TypeCNAME || rrtype == dns.TypeSOA {
					fmt.Printf("%v\n", r)
				}
			}
		}
	}
}
