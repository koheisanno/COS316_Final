package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/dropbox/goebpf"
)

func main() {
	interfaceName := flag.String("interface", "lo", "interface name")
	action := flag.String("action", "start", "action")
	ipAddress := flag.String("ip", "10.10.10.10", "ip address")

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
		fmt.Printf("xdp.Attach(): %v", err)
	}
	err = xdp.Attach(*interfaceName)
	if err != nil {
		log.Fatalf("Error attaching to Interface: %s", err)
	}

	log.Println(*action)

	if *action == "add" {
		blacklist := bpf.GetMapByName("blacklist")
		if blacklist == nil {
			log.Fatalf("eBPF map 'blacklist' not found\n")
		}
		AddIPAddress(blacklist, *ipAddress)
	} else if *action == "stop" {
		xdp.Detach()
	} else {
		defer xdp.Detach()
		ctrlC := make(chan os.Signal, 1)
		signal.Notify(ctrlC, os.Interrupt)
		log.Println("XDP Program Loaded successfuly into the Kernel.")
		log.Println("Press CTRL+C to stop.")
		<-ctrlC
	}
}

// The Function That adds the IPs to the blacklist map
func AddIPAddress(blacklist goebpf.Map, ipAddress string) error {
	log.Println(goebpf.CreateLPMtrieKey(ipAddress))
	err := blacklist.Insert(goebpf.CreateLPMtrieKey(ipAddress), ipAddress)
	if err != nil {
		return err
	}
	return nil
}
