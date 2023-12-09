package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

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
		fmt.Printf("xdp.Attach(): %v", err)
	}
	err = xdp.Attach(*interfaceName)
	if err != nil {
		log.Fatalf("Error attaching to Interface: %s", err)
	}
	blacklist := bpf.GetMapByName("blacklist")
	if blacklist == nil {
		log.Fatalf("eBPF map 'blacklist' not found\n")
	}
	log.Println("XDP Program Loaded successfuly into the Kernel.")

	defer xdp.Detach()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	log.Println("XDP Program Loaded successfuly into the Kernel.")
	log.Println("Press CTRL+C or type 'quit' to stop.")
	<-ctrlC

	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimRight(line, " \t\r\n")
		if err != nil {
			break
		} else if line == "quit" {
			log.Println("Detached")
			xdp.Detach()
			break
		} else {
			action := strings.Split(line, " ")[0]

			if action == "add" {
				ip := strings.Split(line, " ")[1]
				log.Println("add" + ip)

				AddIPAddress(blacklist, ip)
			}
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
