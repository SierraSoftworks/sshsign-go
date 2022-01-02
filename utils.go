package sshsign

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"

	"golang.org/x/crypto/ssh"
)

// The getHash method will resolve a hashing algorithm based on an algorithm
// name and it used to determine how the data should be hashed for a compatible
// hash output in a given signature.
func getHash(algo string) (hash.Hash, error) {
	switch algo {
	case SHA256:
		return sha256.New(), nil
	case SHA512:
		return sha512.New(), nil
	default:
		return nil, ErrUnsupportedHashAlgorithm
	}
}

// The getSecureSigner method will upgrade an RSA signer to use rsa-sha2-512
// as the hashing algorithm for signing data, avoiding the use of the default
// rsa-sha algorithm (which uses SHA-1 and is explicitly not supported by OpenSSL
// for the signing of data).
func getSecureSigner(s ssh.Signer) ssh.Signer {
	if s == nil {
		return s
	}

	if s.PublicKey().Type() != ssh.KeyAlgoRSA && s.PublicKey().Type() != ssh.CertAlgoRSAv01 {
		return s
	}

	as, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		return s
	}

	return &secureSigner{as}
}

// The secureSigner is a wrapper around the default ssh.Signer which is
// used to ensure we don't use outdated (SHA-1) hash algorithms for data
// being signed.
type secureSigner struct {
	s ssh.AlgorithmSigner
}

func (s *secureSigner) PublicKey() ssh.PublicKey {
	return s.s.PublicKey()
}

func (s *secureSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.s.SignWithAlgorithm(rand, data, "rsa-sha2-512")
}
