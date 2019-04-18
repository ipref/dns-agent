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
	initial_delay int = 307 // initial max delay [s]
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

	log.SetFlags(0)

	toks := strings.Split(os.Args[0], "/")
	prog := toks[len(toks)-1]

	parse_cli(prog)

	log.Printf("starting %v\n", prog)

	goexit = make(chan string, 1)
	go catch_signals()

	rand.Seed(time.Now().UnixNano())

	mdataq = make(chan *MapData, MDATAQLEN)

	go broker()

	// determine sources to poll

	specs := make(map[string]bool)

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

		for _, server := range strings.Split(toks[2], ",") {

			if strings.Index(server, ":") < 0 {
				server = server + ":53"
			}

			specs[local_domain+":"+ipref_domain+":"+server] = true
		}
	}

	// poll data sources

	if len(specs) > 0 {
		for spec, _ := range specs {
			go poll_a_source(spec)
		}
	} else {
		goexit <- "no valid source specifications"
	}

	msg := <-goexit
	log.Printf("exiting %v: %v", prog, msg)
}
