/* Copyright (c) 2018-2021 Waldemar Augustyn */

package main

import (
	"flag"
	"log"
	"strings"
)

var cli struct {
	debug      bool
	devmode    bool
	poll_ivl   int // [min]
	mapper_url string
	stamps     bool
	// derived
	specs    []string
	sockname string
}

func parse_cli(prog string) {

	log.SetFlags(0)

	flag.BoolVar(&cli.debug, "debug", false, "print debug information")
	flag.BoolVar(&cli.devmode, "devmode", false, "development mode, run standalone without connecting to mapper")
	flag.StringVar(&cli.mapper_url, "m", "unix:///run/ipref/mapper.sock", "mapper url")
	flag.IntVar(&cli.poll_ivl, "t", 59, "approximate transfer interval in minutes")
	flag.BoolVar(&cli.stamps, "time-stamps", false, "print logs with time stamps")
	flag.Usage = func() {

		log.Println("DNS agent for IPREF mappers. It maps published IPREF addresses")
		log.Println("to IP addresses of local hosts. The match occurs if a host has")
		log.Println("an IPREF address advertised by a public DNS server and an IP")
		log.Println("address advertised by a local DNS server. Only the host portions")
		log.Println("of DNS names must match. Normally, the IPREF addresses and their")
		log.Println("corresponding IP addresses are listed with different domains. It")
		log.Println("is possible to list both addresses with the same domain in split")
		log.Println("horizon configurations (not recommended). DNS agent relies on")
		log.Println("zone transfer protocol, AXFR, to fetch information about IPREF")
		log.Println("addresses. IP addresses of local hosts are obtained via simple")
		log.Println("DNS queries.")
		log.Println("")
		log.Println(" ", prog, "[FLAGS] LOCAL:PUBLIC:SERVERS ...")
		log.Println("")
		log.Println("where:")
		log.Println("")
		log.Println("  LOCAL   - DNS domain for local IP addresses")
		log.Println("  PUBLIC  - DNS domain for public IPREF addresses")
		log.Println("  SERVERS - comma separated list of servers hosting PUBLIC")
		log.Println("            domain: SERVER[:PORT],...")
		log.Println("")
		log.Println("options:")
		log.Println("")
		flag.PrintDefaults()
		log.Println("")
		log.Println("example:")
		log.Println("")
		log.Println("  ", prog, "example.org:example.com:ns1.example.net,ns2.example.net")
		log.Println("")
		log.Println("In this example, hosts on local network publish their private")
		log.Println("IP addresses at locally accessible domain example.org. The")
		log.Println("same hosts publish their public IPREF addresses at publicly")
		log.Println("accessible domain example.com which is hosted on two servers:")
		log.Println("ns1.example.net and ns2.example.net.")
		log.Println("")
	}
	flag.Parse()

	if cli.stamps {
		log.SetFlags(log.Ltime | log.Lmicroseconds)
	}

	cli.specs = flag.Args()

	// validate poll interval

	if cli.poll_ivl < 1 {
		cli.poll_ivl = 1
	}
	if cli.poll_ivl > 10080 {
		cli.poll_ivl = 10080 // one week
	}

	// validate mapper url

	if strings.HasPrefix(cli.mapper_url, "unix:///") {
		cli.sockname = cli.mapper_url[7:]
	} else {
		log.Fatal("FATL unsupported mapper protocol: %v", cli.mapper_url)
	}
}
