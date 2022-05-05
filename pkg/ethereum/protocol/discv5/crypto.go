package discv5

const (
	// Encryption/authentication parameters.
	aesKeySize   = 16
	gcmNonceSize = 12
)

// Nonce represents a nonce used for AES/GCM.
type Nonce [gcmNonceSize]byte
