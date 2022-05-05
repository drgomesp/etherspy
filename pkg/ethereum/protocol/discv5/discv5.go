// Package discv5 implements the Discovery v5 Wire Protocol.
// https://github.com/ethereum/devp2p/blob/master/discv4.md
package discv5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"net"
)

const MaxPacketSize = 1280

// Packet header flag values.
const (
	flagMessage = iota
	flagWhoareyou
	flagHandshake
)

type NodeID [32]byte

var protocolID = [6]byte{'d', 'i', 's', 'c', 'v', '5'}

// Errors.
var (
	errTooShort            = errors.New("packet too short")
	errInvalidHeader       = errors.New("invalid packet header")
	errInvalidFlag         = errors.New("invalid flag value in header")
	errMinVersion          = errors.New("version of packet header below minimum")
	errMsgTooShort         = errors.New("message/handshake packet below minimum size")
	errAuthSize            = errors.New("declared auth size is beyond packet length")
	errUnexpectedHandshake = errors.New("unexpected auth response, not in handshake")
	errInvalidAuthKey      = errors.New("invalid ephemeral pubkey")
	errNoRecord            = errors.New("expected ENR in handshake but none sent")
	errInvalidNonceSig     = errors.New("invalid ID nonce signature")
	errMessageTooShort     = errors.New("message contains no data")
	errMessageDecrypt      = errors.New("cannot decrypt message")
)

// Protocol constants.
const (
	version         = 1
	minVersion      = 1
	sizeofMaskingIV = 16

	minMessageSize      = 48 // this refers to data after static headers
	randomPacketMsgSize = 20
)

type PacketKind byte

func (p PacketKind) String() string {
	switch p {

	default:
		return "UNKNOWN"
	}
}

// Packet sizes.
var (
	sizeofStaticHeader      = binary.Size(StaticHeader{})
	sizeofWhoareyouAuthData = binary.Size(whoareyouAuthData{})
	sizeofHandshakeAuthData = binary.Size(handshakeAuthData{}.h)
	sizeofMessageAuthData   = binary.Size(messageAuthData{})
	sizeofStaticPacketData  = sizeofMaskingIV + sizeofStaticHeader
)

const (
	PacketPing = PacketKind(iota + 1)
	PacketPong
	PacketFindNode
	PacketNodes
	PacketTalkRequest
	PacketTalkResponse
	PacketTicket
	PacketRegTopic
	PacketRegConfirmation
	PacketTopicQuery
	PacketUnknown   = PacketKind(255)
	PacketWhoAreYou = PacketKind(255 - 1)
)

type Packet interface {
	Name() string
	Kind() PacketKind
	RequestID() []byte
	SetRequestID([]byte)
}

type Ping struct {
	ReqID  []byte
	ENRSeq uint64
}

type Pong struct {
	ReqID  []byte
	ENRSeq uint64
	ToIP   net.IP
	ToPort uint16
}

func (p *Ping) Name() string              { return "PING" }
func (p *Ping) Kind() PacketKind          { return PacketPing }
func (p *Ping) RequestID() []byte         { return p.ReqID }
func (p *Ping) SetRequestID(bytes []byte) { p.ReqID = bytes }

func (p *Pong) Name() string              { return "Pong" }
func (p *Pong) Kind() PacketKind          { return PacketPong }
func (p *Pong) RequestID() []byte         { return p.ReqID }
func (p *Pong) SetRequestID(bytes []byte) { p.ReqID = bytes }

func Decode(buf []byte, nid enode.ID) (Packet, error) {
	// Unmask the static header.
	if len(buf) < sizeofStaticPacketData {
		return nil, errTooShort
	}
	var head Header
	copy(head.IV[:], buf[:sizeofMaskingIV])
	mask := head.mask(nid)
	staticHeader := buf[sizeofMaskingIV:sizeofStaticPacketData]
	mask.XORKeyStream(staticHeader, staticHeader)

	reader := bytes.NewReader(buf)
	// Decode and verify the static header.
	reader.Reset(staticHeader)
	binary.Read(reader, binary.BigEndian, &head.StaticHeader)
	remainingInput := len(buf) - sizeofStaticPacketData
	if err := head.checkValid(remainingInput); err != nil {
		return nil, errInvalidHeader
	}

	// Unmask auth data.
	authDataEnd := sizeofStaticPacketData + int(head.AuthSize)
	authData := buf[sizeofStaticPacketData:authDataEnd]
	mask.XORKeyStream(authData, authData)
	head.AuthData = authData

	return nil, errors.New("TODO")
}
