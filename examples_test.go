package sshsign_test

import (
	"bytes"
	"fmt"
	"io/ioutil"

	"github.com/SierraSoftworks/sshsign-go"
	"golang.org/x/crypto/ssh"
)

// This shows an example of how to use the sshsign package to sign
// an arbitrary string using your SSH private key.
func ExampleSigner() {
	// NOTE: We're not handling errors here, but you really should
	pkc, _ := ioutil.ReadFile("./testdata/id_rsa.test")
	pk, _ := ssh.ParsePrivateKey(pkc)

	signer := sshsign.DefaultSigner("tests", "sha512", pk)
	sig, _ := signer.Sign(bytes.NewBufferString("this is some test data"))

	armoured, _ := sig.MarshalArmoured()
	fmt.Println(string(armoured))

	// Output:
	// -----BEGIN SSH SIGNATURE-----
	// U1NIU0lHAAAAAQAAAJcAAAAHc3NoLXJzYQAAAAMBAAEAAACBALjB6dVJyak8JY/G
	// 2j0snID9piF8B/eY5g6RBp3qx64k9wCPz55TGbDFQMkXBzKYVfyRnqRlAPc/1EBW
	// EHQaPQLabjFh565/eOyBBPK4k9kf8AOL2Km2dWH8qaAr5Wb3yyJVlYKjg3CH4zGQ
	// zsORbOhGQ4uRhd3mrQujUlwSY+YLAAAABXRlc3RzAAAAAAAAAAZzaGE1MTIAAACU
	// AAAADHJzYS1zaGEyLTUxMgAAAIBzjsl8QstZs09/pFxfQtvRvGF5xMBxbxw41zkj
	// p6z55jnZ45l/pQa35sDFnzqol5WhT2IfkLnhi9b4Yum8XX8Z9BCKh6/dPrxpMtyj
	// I+ju6vnYZrRZ1i3JihkfstqYnvu3YGc26BBB9Xc254g0IK6rb4VjWAynx3I9an+z
	// q/eRMg==
	// -----END SSH SIGNATURE-----
}

// This shows an example of how to use the sshsign package to verify
// a signature against some arbitrary data. It takes advantage of the
// SSH public key which is embedded in the signature and does not
// validate that the public key is trusted.
func ExampleVerifier() {
	// NOTE: We're not handling errors here, but you really should
	sig, _, _ := sshsign.UnmarshalArmoured([]byte(`-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAJcAAAAHc3NoLXJzYQAAAAMBAAEAAACBALjB6dVJyak8JY/G
2j0snID9piF8B/eY5g6RBp3qx64k9wCPz55TGbDFQMkXBzKYVfyRnqRlAPc/1EBW
EHQaPQLabjFh565/eOyBBPK4k9kf8AOL2Km2dWH8qaAr5Wb3yyJVlYKjg3CH4zGQ
zsORbOhGQ4uRhd3mrQujUlwSY+YLAAAABXRlc3RzAAAAAAAAAAZzaGE1MTIAAACU
AAAADHJzYS1zaGEyLTUxMgAAAIBzjsl8QstZs09/pFxfQtvRvGF5xMBxbxw41zkj
p6z55jnZ45l/pQa35sDFnzqol5WhT2IfkLnhi9b4Yum8XX8Z9BCKh6/dPrxpMtyj
I+ju6vnYZrRZ1i3JihkfstqYnvu3YGc26BBB9Xc254g0IK6rb4VjWAynx3I9an+z
q/eRMg==
-----END SSH SIGNATURE-----
`))

	// TODO: You should check that you trust this public key to sign the data you're validating
	pk, _ := sig.GetPublicKey()
	fmt.Println("Fingerprint:", ssh.FingerprintSHA256(pk))

	verifier := sshsign.DefaultVerifier("tests", "sha512")
	err := verifier.Verify(bytes.NewBufferString("this is some test data"), sig)
	fmt.Println("Validation Error:", err)

	// Output:
	// Fingerprint: SHA256:7qMIR0olZjqCDgLDiZONgDrHxE7d/LvKR7d5b4NlcFA
	// Validation Error: <nil>
}
