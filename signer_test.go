package sshsign_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"

	"github.com/SierraSoftworks/sshsign-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestRoundTrip(t *testing.T) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "private key should be generated correctly")

	ss, err := ssh.NewSignerFromKey(pk)
	require.NoError(t, err, "signer should be generated correctly")

	signer := sshsign.DefaultSigner("test", "sha512", ss)

	data := getRandomData(1024)

	sig, err := signer.Sign(bytes.NewBuffer(data))
	require.NoError(t, err, "signature should be generated correctly")

	assert.NotNil(t, sig, "signature should not be nil")
	assert.Equal(t, "sha512", sig.HashAlgorithm)
	assert.Equal(t, "test", sig.Namespace)

	verifier := sshsign.DefaultVerifier("test", "sha512")
	assert.NoError(t, verifier.Verify(bytes.NewBuffer(data), sig))
}

func getRandomData(n int) []byte {
	data := bytes.NewBuffer(nil)
	io.CopyN(data, rand.Reader, 1024)

	return data.Bytes()
}
