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
	fuzz int = 29 // interval variation [%]

	SRVDATAQLEN = 4
	QRMDATAQLEN = 4
	HOSTREQQLEN = 2
	SENDREQQLEN = 2
)

var goexit chan (string)

// return non-zero random number
func new_batchid() uint32 {

	for {
		batchid := rand.Uint32()
		if batchid != 0 {
			return batchid
		}
	}
}

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

	sources = make(map[string][]string)
	aggdata = make(map[string]AggData)
	hostdata = make(map[string]HostData)

	srvdataq = make(chan SrvData, SRVDATAQLEN)
	qrmdataq = make(chan SrvData, QRMDATAQLEN)
	hostreqq = make(chan HostReq, HOSTREQQLEN)
	sendreqq = make(chan SendReq, SENDREQQLEN)

	go mclient_conn()
	go broker()

	// determine sources to poll

	sources = make(map[string][]string)

	for _, spec := range cli.specs {

		// LOCAL:PUBLIC:SERVER[:PORT],SERVER[:PORT]

		toks := strings.SplitN(spec, ":", 3)

		if len(toks) < 3 {
			log.Printf("E invalid source specification: %v", spec)
			continue
		}

		local_domain := toks[0]
		ipref_domain := toks[1]

		strings.TrimRight(local_domain, ".")
		strings.TrimRight(ipref_domain, ".")

		if len(local_domain) == 0 || len(ipref_domain) == 0 {
			log.Printf("E missing local or public domain: %v", spec)
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
				log.Printf("E empty server: %v", spec)
				continue
			}

			dedup_srvs[srv] = true
		}

		if len(dedup_srvs) == 0 {
			log.Printf("E missing servers: %v", spec)
			continue
		}

		servers := make([]string, 0, len(dedup_srvs))
		for server := range dedup_srvs {
			servers = append(servers, server)
		}

		sources[local_domain+":"+ipref_domain] = servers
	}

	// poll data sources, each server poll spread evently across the poll interval

	if len(sources) > 0 {

		for source, servers := range sources {

			offset := (cli.poll_ivl * 60) / len(servers)
			delay := rand.Intn(offset / 2)

			for _, server := range servers {
				go poll_a_source(source, server, delay)
				delay += offset
			}
		}

	} else {
		goexit <- "no valid source specifications"
	}

	msg := <-goexit
	log.Printf("exiting %v: %v", prog, msg)
}
