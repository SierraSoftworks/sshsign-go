package sshsign

import (
	"crypto/rand"
	"io"

	"github.com/SierraSoftworks/sshsign-go/internal/railway"
	"github.com/SierraSoftworks/sshsign-go/internal/sshbuf"
	"golang.org/x/crypto/ssh"
)

// The Signer interface describes something that is able to generate an
// SSH signature for a given piece of data.
type Signer interface {
	Sign(data io.Reader) (*Signature, error)
}

// DefaultSigner retrieves the default implementation of the Signer
// interface for the given namespace and ssh.Signer. It is able to
// generate signatures for arbitrary data.
func DefaultSigner(namespace, hash string, signer ssh.Signer) Signer {
	return &defaultSigner{
		namespace,
		hash,
		signer,
	}
}

type defaultSigner struct {
	namespace string
	hash      string
	signer    ssh.Signer
}

func (s *defaultSigner) Sign(data io.Reader) (*Signature, error) {
	rw := railway.New()
	hash, err := getHash(s.hash)
	if err != nil {
		return nil, err
	}

	if s.signer == nil {
		return nil, ErrInvalidSigner
	}

	rw.MustInt64(io.Copy(hash, data))

	h_message := hash.Sum([]byte{})

	buf := new(sshbuf.Buffer)
	rw.MustInt(buf.Write([]byte(MAGIC)))
	rw.Must(buf.WriteString(s.namespace))
	rw.Must(buf.WriteString(""))
	rw.Must(buf.WriteString("sha512"))
	rw.Must(buf.WriteBinary(h_message))

	if rw.Err() != nil {
		return nil, rw.Err()
	}

	// Ensure that we're using a supported signing algorithm
	signer := getSecureSigner(s.signer)

	signature, err := signer.Sign(rand.Reader, buf.Bytes())
	if err != nil {
		return nil, err
	}

	return &Signature{
		Version:       1,
		PublicKey:     s.signer.PublicKey().Marshal(),
		Namespace:     s.namespace,
		HashAlgorithm: "sha512",
		Signature:     ssh.Marshal(signature),
	}, nil
}
