# sshsign
**Sign data using your SSH key within Go**

Cryptographic signatures form a critical part of integrity and provenance
for many modern systems. The traditional means for handling this has been
X.509 certificates, however these can be complex to manage especially for
simple use-cases. Alternatives like PGP/GPG reduce this complexity but
offer reduced security (due to their use of outdated cryptographic protocols)
and others like signify and minisign are not widely adopted.

Something that is widely adopted is SSH keys, which most folks reading this
will be very familiar with. As of OpenSSH 8.0 there is a standardized protocol
for using your SSH keys to sign arbitrary files and then verify those signatures,
making it easy to leverage a modern, widely adopted, crypto-system for general
signature validation. Unfortunately, the Go `x/crypto/ssh` package doesn't provide
support for using this functionality out of the box, hence the introduction of
this package.

## Features
 - Sign and verify data using SSH keys.
 - Full integration with the `x/crypto/ssh` library.
 - Fully compatible with `ssh-keygen`'s signing outputs.
 - Simple interface with streaming data support for large files.

## Example

```go
package main

import (
    "log"
    "io"
    "io/ioutil"

    "github.com/SierraSoftworks/sshsign-go"
	"golang.org/x/crypto/ssh"
)

func main() {
    armoured := sign("/path/to/file.txt", "/path/to/id_rsa")
    log.Printf("Signature:\n %s\n", string(armoured))

    signedBy := verify("/path/to/file.txt", armoured)
    log.Printf("Signed by: %s\n", signedBy)
}

func sign(file, key string) string {
    privateKeyBytes, err := ioutil.ReadFile(key)
    must(err)
    
    privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
    must(err)

    file, err := io.Open(file)
    must(err)
    defer f.Close()

    signer := sshsign.DefaultSigner("file", sshsign.SHA512, privateKey)
    sig, err := signer.Sign(file)
    must(err)

    armoured, err := sig.MarshalArmoured()
    must(err)
}

func verify(file, signature string) string {
    sig, err := sshsign.UnmarshalArmoured([]byte(signature))
    must(err)

    file, err := io.Open(file)
    must(err)
    defer f.Close()

    verifier := sshsign.DefaultVerifier("file", sshsign.SHA512)
    must(verifier.Verify(file, sig))

    publicKey, err := sig.PublicKey()
    must(err)
    
    return ssh.FingerprintSHA256(publicKey)
}

func must(err error) {
    if err != nil {
        log.Fatalln(err)
    }
}
```

## References
1. [OpenSSH SSHSIG Protocol Documentation](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)