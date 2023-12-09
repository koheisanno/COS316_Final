package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/dropbox/goebpf"
)

func main() {
	interfaceName := flag.String("interface", "lo", "interface name")
	flag.Parse()

	// Load XDP Into App
	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf("bpf/xdp.elf")
	if err != nil {
		log.Fatalf("LoadELF() failed: %s", err)
	}
	xdp := bpf.GetProgramByName("firewall")
	if xdp == nil {
		log.Fatalln("Program 'firewall' not found in Program")
	}
	err = xdp.Load()
	if err != nil {
		fmt.Printf("xdp.Load(): %v", err)
	}
	err = xdp.Attach(*interfaceName)
	if err != nil {
		log.Fatalf("xdp.Attach(): %s", err)
	}
	blacklist := bpf.GetMapByName("blacklist")
	if blacklist == nil {
		log.Fatalf("eBPF map 'blacklist' not found\n")
	}
	log.Println("XDP Program Loaded successfuly into the Kernel.")

	// Go signal notification works by sending `os.Signal`
	// values on a channel. We'll create a channel to
	// receive these notifications (we'll also make one to
	// notify us when the program can exit).
	sigs := make(chan os.Signal, 1)

	// `signal.Notify` registers the given channel to
	// receive notifications of the specified signals.
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	msg := make(chan string, 1)
	reader := bufio.NewReader(os.Stdin)
	go func() {
		// Receive input in a loop
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				log.Println("Detached")
				xdp.Detach()
				return
			}
			line = strings.TrimRight(line, " \t\r\n")
			if line == "quit" {
				log.Println("Detached")
				xdp.Detach()
				return
			}
			log.Println("Input: ", line)
			// Send what we read over the channel
			msg <- line
		}
	}()

loop:
	for {
		select {
		case <-sigs:
			log.Println("Detached")
			xdp.Detach()
			// Break out of the outer for statement and end the program
			break loop
		case s := <-msg:
			if s == "quit" {
				log.Println("Detached")
				xdp.Detach()
				break loop
			} else {
				action := strings.Split(s, " ")[0]

				if action == "add" {
					ip := strings.Split(s, " ")[1]
					log.Println("add" + ip)

					AddIPAddress(blacklist, ip)
				}
			}
		}
	}
}

// The Function That adds the IPs to the blacklist map
func AddIPAddress(blacklist goebpf.Map, ipAddress string) error {
	log.Printf("Adding %s to blacklist", goebpf.CreateLPMtrieKey(ipAddress))
	err := blacklist.Insert(goebpf.CreateLPMtrieKey(ipAddress), 0)
	if err != nil {
		return err
	}
	return nil
}
