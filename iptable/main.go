package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/dropbox/goebpf"
)

func main() {
	// Go signal notification works by sending `os.Signal`
	// values on a channel. We'll create a channel to
	// receive these notifications (we'll also make one to
	// notify us when the program can exit).
	sigs := make(chan os.Signal, 1)

	// `signal.Notify` registers the given channel to
	// receive notifications of the specified signals.
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	msg := make(chan string, 1)
	go func() {
		// Receive input in a loop
		for {
			var s string
			fmt.Scan(&s)
			// Send what we read over the channel
			msg <- s
		}
	}()

loop:
	for {
		select {
		case <-sigs:
			fmt.Println("Got shutdown, exiting")
			// Break out of the outer for statement and end the program
			break loop
		case s := <-msg:
			fmt.Println("Echoing: ", s)
		}
	}
}

// The Function That adds the IPs to the blacklist map
func AddIPAddress(blacklist goebpf.Map, ipAddress string) error {
	log.Println(goebpf.CreateLPMtrieKey(ipAddress))
	err := blacklist.Insert(goebpf.CreateLPMtrieKey(ipAddress), 0)
	if err != nil {
		return err
	}
	return nil
}
