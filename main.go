package main

import (
	"fmt"
	"github.com/miekg/dns"
)

func main() {

	t := new(dns.Transfer)
	m := new(dns.Msg)
	//t.TsigSecret = map[string]string{"axfr.": "so6ZGir4GPAqINNh9U5c3A=="}
	m.SetAxfr("wdmsys.com.")
	//m.SetTsig("axfr.", dns.HmacMD5, 300, time.Now().Unix())
	c, err := t.In(m, "192.168.84.7:53")
	if err != nil {
		fmt.Printf("transfer failed: %v\n", err)
	}
	for e := range c {
		if e.Error != nil {
			fmt.Printf("envelope error: %v\n", e.Error)
		} else {
			for _, r := range e.RR {
				fmt.Printf("%v\n", r)
			}
		}
	}
}
