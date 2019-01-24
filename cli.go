/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"flag"
	"log"
	"strings"
)

var cli struct {
	debug      bool
	poll_ivl   int // [min]
	mapper_url string
	// derived
	mappings []string
	sockname string
}

func parse_cli(prog string) {

	flag.BoolVar(&cli.debug, "debug", false, "print debug information")
	flag.StringVar(&cli.mapper_url, "m", "unix:///var/run/ipref-mapper.sock", "mapper url")
	flag.IntVar(&cli.poll_ivl, "t", 59, "approximate transfer interval in minutes")
	flag.Usage = func() {
		log.Println("DNS agent for IPREF mappers. It gathers information about published IPREF")
		log.Println("addresses referring to hosts on local network. This information is used for")
		log.Println("proper mapping of IPREF addresss to local network addresses.")
		log.Println("")
		log.Println("   ", prog, "[FLAGS] LOCAL:ZONE:SERVER[:PORT] ...")
		log.Println("")
		flag.PrintDefaults()
	}
	flag.Parse()

	cli.mappings = flag.Args()

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
		log.Fatal("unsupported mapper protocol: %v", cli.mapper_url)
	}
}
