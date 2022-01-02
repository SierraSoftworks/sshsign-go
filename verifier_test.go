package sshsign_test

import (
	"bytes"
	"testing"

	"github.com/SierraSoftworks/sshsign-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifier(t *testing.T) {
	sample_raw := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAJcAAAAHc3NoLXJzYQAAAAMBAAEAAACBALjB6dVJyak8JY/G2j0snI
D9piF8B/eY5g6RBp3qx64k9wCPz55TGbDFQMkXBzKYVfyRnqRlAPc/1EBWEHQaPQLabjFh
565/eOyBBPK4k9kf8AOL2Km2dWH8qaAr5Wb3yyJVlYKjg3CH4zGQzsORbOhGQ4uRhd3mrQ
ujUlwSY+YLAAAABXRlc3RzAAAAAAAAAAZzaGE1MTIAAACUAAAADHJzYS1zaGEyLTUxMgAA
AIAQowvH0RXePCWnCzMQdebEIWGyc+iHM84tUpJ4d/2TkliUS2baG9GuBsu6HB4Rlc9dmp
StHlohL7ilyV4DT/p8jDj5eLw+N758lgtKIPdhG8ZYBTokH4T+KfIGWv9XDLzLo0HaF52s
bdAOS7zmQGR54OZvsEv1gdimOCnR5BGt1Q==
-----END SSH SIGNATURE-----
`
	sample, _, err := sshsign.UnmarshalArmoured([]byte(sample_raw))
	require.NoError(t, err)

	t.Run("with the right parameters", func(t *testing.T) {
		verifier := sshsign.DefaultVerifier("tests", "sha512")
		assert.NoError(t, verifier.Verify(bytes.NewBufferString("test"), sample))
	})

	t.Run("with the wrong namespace", func(t *testing.T) {
		verifier := sshsign.DefaultVerifier("file", "sha512")
		assert.EqualError(t, verifier.Verify(bytes.NewBufferString("test"), sample), sshsign.ErrInvalidNamespace.Error())
	})

	t.Run("with the wrong hash algorithm", func(t *testing.T) {
		verifier := sshsign.DefaultVerifier("tests", "sha256")
		assert.EqualError(t, verifier.Verify(bytes.NewBufferString("test"), sample), sshsign.ErrInvalidHashAlgorithm.Error())
	})

	t.Run("with the wrong data", func(t *testing.T) {
		verifier := sshsign.DefaultVerifier("tests", "sha512")
		assert.EqualError(t, verifier.Verify(bytes.NewBufferString("tampered"), sample), sshsign.ErrInvalidSignature.Error())
	})
}
