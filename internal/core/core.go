package core

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func ListInterfaces() {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for i, v := range devs {
		fmt.Println("=====================================")
		fmt.Printf(" Interface #%d\n", i)
		fmt.Println("=====================================")
		fmt.Printf(" Name          : %s\n", v.Name)
		fmt.Printf(" Addresses     :\n")
		for _, addr := range v.Addresses {
			fmt.Printf("   - %s\n", addr.IP)
		}
		fmt.Printf(" Description   : %s\n", v.Description)
		fmt.Println()
	}
}

func printDNSData(srcPac gopacket.Packet) {
	if dnsLayer := srcPac.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		dns, _ := dnsLayer.(*layers.DNS)
		fmt.Println("=== DNS Packet ===")
		fmt.Printf("Transaction ID: 0x%04X\n", dns.ID)

		if dns.QR {
			fmt.Println("Type: Response")
		} else {
			fmt.Println("Type: Query")
		}

		fmt.Printf("Opcode: %s | RCode: %s\n", dns.OpCode, dns.ResponseCode)
		fmt.Printf("Flags: AA=%v | TC=%v | RD=%v | RA=%v | Z=%d\n", dns.AA, dns.TC, dns.RD, dns.RA, dns.Z)
		fmt.Printf("Questions: %d | Answers: %d | Authorities: %d | Additionals: %d\n", dns.QDCount, dns.ANCount, dns.NSCount, dns.ARCount)

		if len(dns.Questions) > 0 {
			fmt.Println("\n-- Questions --")
			for _, q := range dns.Questions {
				fmt.Printf("  %s [%s] (Class %d)\n", string(q.Name), q.Type, q.Class)
			}
		}

		if len(dns.Answers) > 0 {
			fmt.Println("\n-- Answers --")
			for _, a := range dns.Answers {
				fmt.Printf("  %s [%s] => %s (TTL: %ds)\n", string(a.Name), a.Type, a.IP.String(), a.TTL)
			}
		}

		if len(dns.Authorities) > 0 {
			fmt.Println("\n-- Authorities --")
			for _, a := range dns.Authorities {
				fmt.Printf("  %s [%s] => %s (TTL: %ds)\n", string(a.Name), a.Type, a.IP.String(), a.TTL)
			}
		}

		if len(dns.Additionals) > 0 {
			fmt.Println("\n-- Additionals --")
			for _, a := range dns.Additionals {
				fmt.Printf("  %s [%s] => %s (TTL: %ds)\n", string(a.Name), a.Type, a.IP.String(), a.TTL)
			}
		}

		fmt.Println("=================")
	}
}

func Start(netInterface string) error {
	conn, err := pcap.OpenLive(netInterface, 65535, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer conn.Close()

	srcPacket := gopacket.NewPacketSource(conn, conn.LinkType())
	for p := range srcPacket.Packets() {
		printDNSData(p)
	}
	return nil
}
