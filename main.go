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

	dataq = make(chan *ZoneData, ZDQLEN)

	go broker()

	// determine zones to poll

	zones := make(map[string]bool)

	for _, mapping := range cli.mappings {

		// LOCAL:PUBLIC:SERVER[:PORT],SERVER[:PORT]

		toks := strings.SplitN(mapping, ":", 3)

		if len(toks) < 3 {
			log.Printf("ERR invalid mapping: %v", mapping)
			continue
		}

		local_zone := toks[0]
		ipref_zone := toks[1]

		if len(local_zone) == 0 || len(ipref_zone) == 0 {
			log.Printf("ERR missing local or public domain: %v", mapping)
			continue
		}

		if local_zone[len(local_zone)-1:] != "." {
			local_zone += "."
		}

		if ipref_zone[len(ipref_zone)-1:] != "." {
			ipref_zone += "."
		}

		for _, server := range strings.Split(toks[2], ",") {

			if strings.Index(server, ":") < 0 {
				server = server + ":53"
			}

			zones[local_zone+":"+ipref_zone+":"+server] = true
		}

	}

	// poll listed zones

	if len(zones) > 0 {
		for zone, _ := range zones {
			go poll_a_zone(zone)
		}
	} else {
		goexit <- "no valid mappings"
	}

	msg := <-goexit
	log.Printf("exit: %v", msg)
}
