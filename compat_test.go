package sshsign_test

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/SierraSoftworks/sshsign-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestCompatibility(t *testing.T) {
	sshkeygenOutput := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAJcAAAAHc3NoLXJzYQAAAAMBAAEAAACBALjB6dVJyak8JY/G2j0snI
D9piF8B/eY5g6RBp3qx64k9wCPz55TGbDFQMkXBzKYVfyRnqRlAPc/1EBWEHQaPQLabjFh
565/eOyBBPK4k9kf8AOL2Km2dWH8qaAr5Wb3yyJVlYKjg3CH4zGQzsORbOhGQ4uRhd3mrQ
ujUlwSY+YLAAAABXRlc3RzAAAAAAAAAAZzaGE1MTIAAACUAAAADHJzYS1zaGEyLTUxMgAA
AIAQowvH0RXePCWnCzMQdebEIWGyc+iHM84tUpJ4d/2TkliUS2baG9GuBsu6HB4Rlc9dmp
StHlohL7ilyV4DT/p8jDj5eLw+N758lgtKIPdhG8ZYBTokH4T+KfIGWv9XDLzLo0HaF52s
bdAOS7zmQGR54OZvsEv1gdimOCnR5BGt1Q==
-----END SSH SIGNATURE-----
`

	t.Run("verifies ssh-keygen output", func(t *testing.T) {
		sig, _, err := sshsign.UnmarshalArmoured([]byte(sshkeygenOutput))
		require.NoError(t, err)

		verifier := sshsign.DefaultVerifier("tests", "sha512")
		assert.NoError(t, verifier.Verify(bytes.NewBufferString("test"), sig))
	})

	t.Run("generates identical output to ssh-keygen", func(t *testing.T) {
		pkc, err := ioutil.ReadFile("testdata/id_rsa.test")
		require.NoError(t, err)

		pk, err := ssh.ParsePrivateKey(pkc)
		require.NoError(t, err)

		signer := sshsign.DefaultSigner("tests", "sha512", pk)
		sig, err := signer.Sign(bytes.NewBufferString("test"))
		require.NoError(t, err)

		armoured, err := sig.MarshalArmoured()
		require.NoError(t, err)

		assertArmouredEqual(t, []byte(armoured), []byte(sshkeygenOutput))
	})
}
