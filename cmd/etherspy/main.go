package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
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
	skip = iota
	PacketPing
	PacketPong
)

func init() {
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Fatal().Err(err).Send()
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			_ = req.Body.Close()
			log.Debug().Msgf("received request from stream", h.net, h.transport, ":", req, "with", bodyBytes, "bytes in request body")
		}
	}
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

	// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

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

			// Get packet information
			ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			lengthPacket := packet.Metadata().Length
			buf := packet.Layers()[3].LayerContents()

			if len(buf) < headSize+1 {
				log.Debug().Msg("packet too small")
				continue
			}

			if udp := packet.TransportLayer().(*layers.UDP); udp == nil {
				continue
			}

			if *logAllPackets {
				spew.Dump(packet)
			}

			hash, sig, sigdata := buf[:macSize], buf[macSize:headSize], buf[headSize:]
			shouldHash := crypto.Keccak256(buf[macSize:])
			if !bytes.Equal(hash, shouldHash) {
				log.Error().Err(errors.New("bad hash")).Send()
				continue
			}

			nid, err := recoverNodeID(crypto.Keccak256(buf[headSize:]), sig)
			if err != nil {
				log.Fatal().Err(err).Send()
			}

			// Print initial info
			log.Debug().Str("time", packet.Metadata().Timestamp.Format("01/02/2006 3:04:05.000000PM")).
				Str("src", ip.SrcIP.String()).
				Str("dst", ip.DstIP.String()).
				Int("len", lengthPacket).
				Str("node", nid.String()).
				Msgf("packet received")

			switch ptype := sigdata[0]; ptype {
			case PacketPing:
				log.Debug().Msgf("PING")
			}

			//assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)

		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}
}

// NodeID is a unique identifier for each node.
// The node identifier is a marshaled elliptic curve public key.
// 512 bits.
type NodeID [64]byte

// String() returns NodeID as a long hexadecimal number.
func (n NodeID) String() string {
	return fmt.Sprintf("%x", n[:])
}

// recoverNodeID computes the public key used to sign the
// given hash from the signature.
func recoverNodeID(hash, sig []byte) (id NodeID, err error) {
	pubkey, err := secp256k1.RecoverPubkey(hash, sig)
	if err != nil {
		return id, err
	}
	if len(pubkey)-1 != len(id) {
		return id, fmt.Errorf("recovered pubkey has %d bits, want %d bits", len(pubkey)*8, (len(id)+1)*8)
	}
	for i := range id {
		id[i] = pubkey[i+1]
	}
	return id, nil
}
