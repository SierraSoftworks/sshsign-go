package sshsign

import (
	"io"

	"github.com/SierraSoftworks/sshsign-go/internal/railway"
	"github.com/SierraSoftworks/sshsign-go/internal/sshbuf"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

// The Verifier interface describes something that is able to verify a
// piece of data against a given SSH signature. It is expected that the
// verifier contains information about the namespace that it should be
// verifying against, as well as the trusted hash algorithm.
type Verifier interface {
	Verify(data io.Reader, sig *Signature) error
}

// The DefaultVerifier constructs a verifier that can check the validity
// of an SSH signature. It requires the namespace and hash algorithm
// that the signature was generated with to be defined as this helps
// prevent cross-protocol attacks and hash algorithm downgrades.
func DefaultVerifier(namespace, hash string) Verifier {
	return &defaultVerifier{
		namespace,
		hash,
	}
}

type defaultVerifier struct {
	namespace string
	hash      string
}

func (d *defaultVerifier) Verify(data io.Reader, sig *Signature) error {
	if sig.Version > 1 {
		return ErrUnsupportedVersion
	}

	if sig.Namespace != d.namespace {
		return ErrInvalidNamespace
	}

	if sig.HashAlgorithm != d.hash {
		return ErrInvalidHashAlgorithm
	}

	hash, err := getHash(sig.HashAlgorithm)
	if err != nil {
		return err
	}

	rw := railway.New()
	rw.MustInt64(io.Copy(hash, data))

	h_message := hash.Sum([]byte{})

	buf := sshbuf.New()
	rw.MustInt(buf.Write([]byte(MAGIC)))
	rw.Must(buf.WriteString(d.namespace))
	rw.Must(buf.WriteString(""))
	rw.Must(buf.WriteString(sig.HashAlgorithm))
	rw.Must(buf.WriteBinary(h_message))

	if rw.Err() != nil {
		return rw.Err()
	}

	key, err := sig.GetPublicKey()
	if err != nil {
		return errors.Wrap(err, "sshsign: failed to read public key")
	}

	var sshsig ssh.Signature
	err = ssh.Unmarshal(sig.Signature, &sshsig)
	if err != nil {
		return errors.Wrap(err, "sshsign: unable to read signature structure")
	}

	err = key.Verify(buf.Bytes(), &sshsig)
	if err != nil {
		return ErrInvalidSignature
	}

	return nil
}
