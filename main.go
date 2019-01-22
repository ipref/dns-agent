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
	parse_cli()

	if len(cli.mappings) == 0 {
		log.Fatal("no zones to poll")
	}

	goexit = make(chan string)
	go catch_signals()

	rand.Seed(time.Now().UnixNano())

	log.Printf("starting %v\n", cli.prog)

	for _, mapping := range cli.mappings {
		go poll_a_zone(string(mapping))
	}

	msg := <-goexit
	log.Printf("exit: %v", msg)
}
