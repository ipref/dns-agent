/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"log"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	interval_fuzz int = 29  // poll interval variation [%]
	initial_delay int = 173 // initial max delay [s]

	MDATAQLEN   = 4
	MREQQLEN    = 8
	MCLIENTQLEN = 8
)

var goexit chan (string)

func catch_signals() {

	sigchan := make(chan os.Signal, 1)
	signal.Notify(sigchan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigchan

	signal.Stop(sigchan)
	goexit <- "signal(" + sig.String() + ")"
}

func main() {

	toks := strings.Split(os.Args[0], "/")
	prog := toks[len(toks)-1]

	parse_cli(prog)

	log.Printf("starting %v\n", prog)

	goexit = make(chan string, 1)
	go catch_signals()

	rand.Seed(time.Now().UnixNano())

	mstat = make(map[string]*MapStatus)

	mdataq = make(chan *MapData, MDATAQLEN)
	mreqq = make(chan *MreqData, MREQQLEN)
	mclientq = make(chan *MreqData, MCLIENTQLEN)

	go mclient_conn()
	go broker()

	// determine sources to poll

	specs := make(map[string]int)

	for _, spec := range cli.specs {

		// LOCAL:PUBLIC:SERVER[:PORT],SERVER[:PORT]

		toks := strings.SplitN(spec, ":", 3)

		if len(toks) < 3 {
			log.Printf("ERR invalid source specification: %v", spec)
			continue
		}

		local_domain := toks[0]
		ipref_domain := toks[1]

		if len(local_domain) == 0 || len(ipref_domain) == 0 {
			log.Printf("ERR missing local or public domain: %v", spec)
			continue
		}

		if local_domain[len(local_domain)-1:] != "." {
			local_domain += "."
		}

		if ipref_domain[len(ipref_domain)-1:] != "." {
			ipref_domain += "."
		}

		servers := strings.Split(toks[2], ",")
		quorum := len(servers)/2 + 1
		for _, server := range servers {

			if strings.Index(server, ":") < 0 {
				server = server + ":53"
			}

			specs[local_domain+":"+ipref_domain+":"+server] = quorum
		}
	}

	// poll data sources

	if len(specs) > 0 {
		for spec, quorum := range specs {
			go poll_a_source(spec, quorum)
		}
	} else {
		goexit <- "no valid source specifications"
	}

	msg := <-goexit
	log.Printf("exiting %v: %v", prog, msg)
}
