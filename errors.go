package sshsign

import "fmt"

var (
	// The ErrInvalidSignature error is raised when the signature cannot be parsed or
	// does not match the expected signature for the data being validated.
	ErrInvalidSignature = fmt.Errorf("invalid signature")

	// The ErrInvalidNamespace error is raised when the namespace embedded in the signature
	// does not match the namespace that the verifier is configured to use. This may indicate
	// an attempt to perform a cross-protocol attack.
	ErrInvalidNamespace = fmt.Errorf("invalid namespace")

	// The ErrInvalidHashAlgorithm error is raised when the hash algorithm embedded in the
	// signature does not match the hash algorithm that the verifier is configured to use.
	// This may indicate an attempt to downgrade the hash algorithm to a weaker one which
	// is vulnerable to a hash collision.
	ErrInvalidHashAlgorithm = fmt.Errorf("invalid hash algorithm")

	// The ErrUnsupportedHashAlgorithm error is raised when the hash algorithm specified
	// either in the signer or in the verifier is not supported by the implementation.
	ErrUnsupportedHashAlgorithm = fmt.Errorf("unsupported hash algorithm")

	// The ErrUnsupportedVersion error is raised when the version embedded in the signature
	// is not supported by the implementation.
	ErrUnsupportedVersion = fmt.Errorf("unsupported version")
)
