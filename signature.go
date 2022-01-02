package sshsign

import (
	"encoding/pem"

	"github.com/SierraSoftworks/sshsign-go/internal/railway"
	"github.com/SierraSoftworks/sshsign-go/internal/sshbuf"
	"golang.org/x/crypto/ssh"
)

// The magic value used to identify an SSH signature.
const MAGIC = "SSHSIG"

// A Signature is used to attest to the content and origin of a piece of data
// through cryptographic signing using an SSH key. It includes the public key
// which was used to sign the data, as well as the namespace that the signature
// was generated for (used to prevent cross-protocol attacks where the same signature
// is re-used for different protocols).
//
// For more information, please consult the documentation on OpenSSH's GitHub:
// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig
type Signature struct {
	Version       uint32
	PublicKey     []byte
	Namespace     string
	reserved      string
	HashAlgorithm string
	Signature     []byte
}

// GetPublicKey returns the reference to the ssh.PublicKey that was used to
// sign the data.
func (s *Signature) GetPublicKey() (ssh.PublicKey, error) {
	return ssh.ParsePublicKey(s.PublicKey)
}

// MarshalArmoured returns the signature as an armoured PEM block which may
// be later decoded using UnmarshalArmoured.
func (s *Signature) MarshalArmoured() ([]byte, error) {
	bin, err := s.MarshalBinary()

	armoured := pem.EncodeToMemory(&pem.Block{
		Type:    "SSH SIGNATURE",
		Headers: map[string]string{},
		Bytes:   bin,
	})

	return armoured, err
}

// MarshalBinary returns the signature as an un-armoured binary blob which
// may be later decoded using UnmarshalBinary. It consists of the same data
// which is used by MarshalArmoured, but without the PEM armouring and base64
// encoding, making it more suitable for data-constrained environments where
// binary transmission is supported.
func (s *Signature) MarshalBinary() ([]byte, error) {
	buf := new(sshbuf.Buffer)
	rw := railway.New()

	rw.MustInt(buf.Write([]byte(MAGIC)))
	rw.Must(buf.WriteUint32(s.Version))
	rw.Must(buf.WriteBinary(s.PublicKey))
	rw.Must(buf.WriteString(s.Namespace))
	rw.Must(buf.WriteString(s.reserved))
	rw.Must(buf.WriteString(s.HashAlgorithm))
	rw.Must(buf.WriteBinary(s.Signature))

	if rw.Err() != nil {
		return nil, rw.Err()
	}

	return buf.Bytes(), nil
}

// UnmarshalArmoured consumes an armoured PEM block and returns a Signature, as
// well as a reference to the remaining data which appears after the signature.
// Under normal use, a signature file should not have any data remaining in the
// `rest` portion of the return value.
func UnmarshalArmoured(data []byte) (sig *Signature, rest []byte, err error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, rest, ErrInvalidSignature
	}

	if block.Type != "SSH SIGNATURE" {
		return nil, rest, ErrInvalidSignature
	}

	sig, err = UnmarshalBinary(block.Bytes)
	return
}

// UnmarshalBinary reconstructs a Signature from a binary blob. It should be
// used to reverse the MarshalBinary operation.
func UnmarshalBinary(data []byte) (*Signature, error) {
	if len(data) < len(MAGIC)+4+1+1+1+1+1 {
		return nil, ErrInvalidSignature
	}

	if string(data[:len(MAGIC)]) != MAGIC {
		return nil, ErrInvalidSignature
	}

	buf := sshbuf.FromBytes(data[len(MAGIC):])
	sig := &Signature{}
	rw := railway.New()

	sig.Version = rw.MustUint32(buf.ReadUint32())
	sig.PublicKey = rw.MustBytes(buf.ReadBinary())
	sig.Namespace = rw.MustString(buf.ReadString())
	sig.reserved = rw.MustString(buf.ReadString())
	sig.HashAlgorithm = rw.MustString(buf.ReadString())
	sig.Signature = rw.MustBytes(buf.ReadBinary())

	return sig, rw.Err()
}
