/* Copyright (c) 2018-2021 Waldemar Augustyn */

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

	DNSDATAQLEN   = 4
	STATEDATAQLEN = 4
	MREQQLEN      = 8
	MCLIENTQLEN   = 8
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

	//mstat = make(map[string]*MapStatus)

	dnsdataq = make(chan DnsData, DNSDATAQLEN)
	statedataq = make(chan StateData, STATEDATAQLEN)
	mreqq = make(chan *MreqData, MREQQLEN)
	mclientq = make(chan *MreqData, MCLIENTQLEN)

	go mclient_conn()
	go broker()

	// determine sources to poll

	sources = make(map[string][]string)

	for _, spec := range cli.specs {

		// LOCAL:PUBLIC:SERVER[:PORT],SERVER[:PORT]

		toks := strings.SplitN(spec, ":", 3)

		if len(toks) < 3 {
			log.Printf("ERR invalid source specification: %v", spec)
			continue
		}

		local_domain := toks[0]
		ipref_domain := toks[1]

		strings.TrimRight(local_domain, ".")
		strings.TrimRight(ipref_domain, ".")

		if len(local_domain) == 0 || len(ipref_domain) == 0 {
			log.Printf("ERR missing local or public domain: %v", spec)
			continue
		}

		srvs := strings.Split(toks[2], ",")
		dedup_srvs := make(map[string]bool)

		for _, srv := range srvs {

			strings.TrimSpace(srv)

			if strings.Index(srv, ":") < 0 {
				srv += ":53"
			}

			if len(srv) < 4 {
				log.Printf("ERR empty server: %v", spec)
				continue
			}

			dedup_srvs[srv] = true
		}

		if len(dedup_srvs) == 0 {
			log.Printf("ERR missing servers: %v", spec)
			continue
		}

		servers := make([]string, 0, len(dedup_srvs))
		for server := range dedup_srvs {
			servers = append(servers, server)
		}

		sources[local_domain+":"+ipref_domain] = servers
	}

	// poll data sources

	if len(sources) > 0 {
		for source, servers := range sources {
			for _, server := range servers {
				go poll_a_source(source, server)
			}
		}
	} else {
		goexit <- "no valid source specifications"
	}

	msg := <-goexit
	log.Printf("exiting %v: %v", prog, msg)
}
