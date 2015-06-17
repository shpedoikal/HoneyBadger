package main

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/bsdbpf"
	"github.com/google/gopacket/layers"
)

func main() {
	var err error
	sniffer := bsdbpf.NewBPFSniffer(os.Args[1], "", 32767, 3)
	err = sniffer.Init()
	if err != nil {
		panic(err)
	}
	for {
		frame, captureInfo, err := sniffer.ReadPacketData()
		if err != nil {
			panic(err)
		}
		// Decode a packet
		fmt.Printf("frame timestamp %s\n", captureInfo.Timestamp)
		packet := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
		// Get the TCP layer from this packet
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			fmt.Println("This is a TCP packet!")
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
		}
		// Iterate over all layers, printing out each layer type
		for _, layer := range packet.Layers() {
			fmt.Println("PACKET LAYER:", layer.LayerType())
		}
	}
}
