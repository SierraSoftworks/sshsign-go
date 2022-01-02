package sshsign

const (
	// The SHA256 hash algorithm may be used to compute a
	// hash for the data that is being signed. This is performed
	// prior to signing to reduce the amount of data that needs
	// to be signed (by using the hash of the data instead of the
	// data itself).
	SHA256 = "sha256"

	// The SHA512 hash algorithm may be used to compute a
	// hash for the data that is being signed. This is performed
	// prior to signing to reduce the amount of data that needs
	// to be signed (by using the hash of the data instead of the
	// data itself).
	//
	// Compared to SHA256, SHA512 offers greater collision resistance
	// and is thus more secure, however it is also more costly to compute.
	// In general, it is recommended that you stick with SHA512 unless
	// your security and performance needs dictate otherwise.
	SHA512 = "sha512"
)
