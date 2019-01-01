/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"fmt"
	"github.com/miekg/dns"
)

func main() {

	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr("ipref.org.")
	c, err := t.In(m, "ns1.dynu.com:53")
	if err != nil {
		fmt.Printf("transfer failed: %v\n", err)
	}
	for e := range c {
		if e.Error != nil {
			fmt.Printf("envelope error: %v\n", e.Error)
		}
		for _, r := range e.RR {
			// only selected records
			rrtype := r.Header().Rrtype
			if rrtype == dns.TypeA || rrtype == dns.TypeTXT || rrtype == dns.TypeSOA {
				fmt.Printf("%v\n", r)
			}
		}

	}
}
