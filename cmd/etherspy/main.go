package main

import (
	"flag"
	"github.com/davecgh/go-spew/spew"
	"github.com/drgomesp/etherspy/pkg/ethereum/protocol/discv4"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
	"time"
)

var iface = flag.String("i", "enp9s0", "Interface to get packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "udp and dst port 30303", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", false, "Logs every packet in great detail")

// Packet sizes
const (
	macSize  = 256 / 8           // 32
	sigSize  = 520 / 8           // 65 (512-bit signature + 1 byte more for recovery id)
	headSize = macSize + sigSize // space of packet frame data
)

// Packet types
const (
	PacketPing = iota + 1
	PacketPong
)

func init() {
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error

	// Set up pcap packet capture
	if *fname != "" {
		log.Info().Msgf("Reading from pcap dump %q", *fname)
		handle, err = pcap.OpenOffline(*fname)
	} else {
		log.Info().Msgf("Starting capture on interface %q", *iface)
		handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal().Err(err).Send()
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal().Err(err).Send()
	}

	log.Info().Msg("reading in packets")

	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	ticker := time.Tick(time.Minute)

	for {
		select {
		case packet := <-packetSource.Packets():
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}

			udp := packet.TransportLayer().(*layers.UDP)
			if udp == nil {
				continue
			}

			if *logAllPackets {
				spew.Dump(packet)
			}

			buf := packet.Layers()[3].LayerContents()

			var (
				hash   []byte
				p      interface{}
				nodeID discv4.NodeID
			)

			if buf != nil {
				hash, p, nodeID, err = discv4.Decode(buf)
				checkError(err)

				_, _ = hash, nodeID
				
				spew.Dump(p)
			}

		case <-ticker:
			log.Trace().Msg("the clock is ticking")
		}
	}
}

func checkError(err error) {
	if err != nil {
		log.Fatal().Err(err).Send()
	}
}
