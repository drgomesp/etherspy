// Package discv4 implements the Discovery v4 Wire Protocol.
// https://github.com/ethereum/devp2p/blob/master/discv4.md
package discv4

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
)

const MaxPacketSize = 1280

const (
	macSize  = 32
	sigSize  = crypto.SignatureLength
	headSize = macSize + sigSize
)

type PacketKind byte

func (p PacketKind) String() string {
	switch p {
	case PacketPing:
		return "PING"
	case PacketPong:
		return "PONG"
	case PacketFindNode:
		return "FIND_NODE"
	case PacketNeighbors:
		return "NEIGHBORS"
	default:
		return "UNKNOWN"
	}
}

const (
	PacketPing = PacketKind(iota + 1)
	PacketPong
	PacketFindNode
	PacketNeighbors
	PacketENRRequest
	PacketENRResponse
)

type Ping struct {
	Version    uint
	From, To   rpcEndpoint
	Expiration uint64
	Rest       []rlp.RawValue `rlp:"tail"`
}

type Pong struct {
	To         rpcEndpoint
	ReplyTok   []byte
	Expiration uint64
	Rest       []rlp.RawValue `rlp:"tail"`
}

type FindNode struct {
	Target     NodeID
	Expiration uint64
	Rest       []rlp.RawValue `rlp:"tail"`
}

type Neighbors struct {
	Nodes      []rpcNode
	Expiration uint64
	Rest       []rlp.RawValue `rlp:"tail"`
}

func Decode(buf []byte) (hash []byte, p interface{}, ptype PacketKind, id NodeID, err error) {
	if len(buf) < headSize+1 {
		return hash, p, 0x0, id, errors.New("packet too small")
	}

	hash, sig, sigdata := buf[:macSize], buf[macSize:headSize], buf[headSize:]
	if !bytes.Equal(hash, crypto.Keccak256(buf[macSize:])) {
		return hash, p, 0x0, id, errors.New("bad hash")
	}

	fromID, err := recoverNodeID(crypto.Keccak256(buf[headSize:]), sig)
	if err != nil {
		return hash, p, 0x0, id, err
	}

	switch ptype = PacketKind(sigdata[0]); ptype {
	case PacketPing:
		p = new(Ping)
	case PacketPong:
		p = new(Pong)
	case PacketFindNode:
		p = new(FindNode)
	case PacketNeighbors:
		p = new(Neighbors)
	default:
		return hash, p, 0x0, id, fmt.Errorf("unknown type: %d", ptype)
	}

	err = rlp.
		NewStream(bytes.NewReader(sigdata[1:]), 0).
		Decode(p)

	return hash, p, ptype, fromID, err
}
