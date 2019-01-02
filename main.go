/* Copyright (c) 2018-2019 Waldemar Augustyn */

package main

import (
	"log"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	interval_fuzz int = 25  // poll interval variation [%]
	initial_delay int = 300 // initial max delay [secs]
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
	parse_cli()

	if len(cli.zones) == 0 {
		log.Fatal("no zones to poll")
	}

	goexit = make(chan string)
	go catch_signals()

	rand.Seed(time.Now().UnixNano())

	for _, zone := range cli.zones {
		go poll_a_zone(string(zone))
	}

	_ = <-goexit
}
