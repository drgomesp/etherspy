package discv5

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// Header represents a packet header.
type Header struct {
	IV [sizeofMaskingIV]byte
	StaticHeader
	AuthData []byte

	src enode.ID // used by decoder
}

// StaticHeader contains the static fields of a packet header.
type StaticHeader struct {
	ProtocolID [6]byte
	Version    uint16
	Flag       byte
	Nonce      Nonce
	AuthSize   uint16
} // Authdata layouts.
type (
	whoareyouAuthData struct {
		IDNonce   [16]byte // ID proof data
		RecordSeq uint64   // highest known ENR sequence of requester
	}

	handshakeAuthData struct {
		h struct {
			SrcID      enode.ID
			SigSize    byte // ignature data
			PubkeySize byte // offset of
		}
		// Trailing variable-size data.
		signature, pubkey, record []byte
	}

	messageAuthData struct {
		SrcID enode.ID
	}
)

// headerMask returns a cipher for 'masking' / 'unmasking' packet headers.
func (h *Header) mask(destID enode.ID) cipher.Stream {
	block, err := aes.NewCipher(destID[:16])
	if err != nil {
		panic("can't create cipher")
	}
	return cipher.NewCTR(block, h.IV[:])
}

// checkValid performs some basic validity checks on the header.
// The packetLen here is the length remaining after the static header.
func (h *StaticHeader) checkValid(packetLen int) error {
	if h.ProtocolID != protocolID {
		return errInvalidHeader
	}
	if h.Version < minVersion {
		return errMinVersion
	}
	if h.Flag != flagWhoareyou && packetLen < minMessageSize {
		return errMsgTooShort
	}
	if int(h.AuthSize) > packetLen {
		return errAuthSize
	}
	return nil
}
