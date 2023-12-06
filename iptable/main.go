package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/dropbox/goebpf"
)

func main() {
	interfaceName := "lo"

	bpf := goebpf.NewDefaultEbpfSystem()
	err := bpf.LoadElf("xdp/xdp.o")
	if err != nil {
		log.Fatalf("LoadELF() failed: %s", err)
	}
	ip_list := bpf.GetMapByName("ip_list")
	if ip_list == nil {
		log.Fatalf("eBPF map 'ip_list' not found\n")
	}
	xdp := bpf.GetProgramByName("xdp_iptable")
	if xdp == nil {
		log.Fatalln("Program 'xdp_iptable' not found in Program")
	}
	err = xdp.Load()
	if err != nil {
		fmt.Printf("xdp.Attach(): %v", err)
	}
	err = xdp.Attach(interfaceName)
	if err != nil {
		log.Fatalf("Error attaching to Interface: %s", err)
	}

	defer xdp.Detach()
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)
	log.Println("XDP Program Loaded successfuly into the Kernel.")
	log.Println("Press CTRL+C to stop.")
	<-ctrlC

}
