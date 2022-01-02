package sshsign_test

import (
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/SierraSoftworks/sshsign-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignature(t *testing.T) {
	armoured := `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAMQN3Iylzh9XlqGfXh/s/C
fH4KDXW7XnT6W0qce08suv16VT+I+jEMgZjvevZXnjVHEmzoZJqGGpbvQlGBd+IQq5++MR
248s5BlSk8nDE3lqoTVjBViLOM/VKSdVg70WwmGFAbQslMiBARw1ZOtA7Q8Nh9nSgmYbrB
Qx8Bpku4olc2xY1xSJT+6pSsMgi9LucLXicuuSKLiyoOHHNgPWfTthfqlmD7NKNuiOGsJc
bhQsrFIPwbz458KCNmOjbhyBF1uDxz7fh5mBUkH9uP6+78k1G/acVNG+qasdufRS2CQBYv
1xAvzjzLClBldHFqsFdEGBFCEffsCL1kET+JSU8J72V+GPPMZze3bapHYROQ61j6ineevp
M9pIq3tS3JKfHCg4wuQTxt8couFp6TyWcwWZ8jYxkWPCKjrnJy4QSNScrSJbY/98Raz5dt
Z7l0fg0AU/6RweZQMgI6lx7c/f7js/fv0OO8izpcc1wizA3GcEWcrtkLT+OP08FXOEoq9k
DwAAAARmaWxlAAAAAAAAAAZzaGE1MTIAAAGUAAAADHJzYS1zaGEyLTUxMgAAAYA42LEV6i
9c7il0g6zPU3MfP/Qs786HkEs50T5jzpTEcJgFhtRBWFUcYhd1wPyZo3N7mSzqSsdWI1MT
jxsl2C/lH3HkDaqNaHe+dF4Ah3m/RoDpv2UB/9yTsGsEJpaO1QRJIqSEFaE+4+N0u7DhHy
G7eBI0r0EO3YGT+QMsoteUSZxskSAHp72q+wvLpywNTIbxHwtzg+FauvTYswmSQpixpUA0
e+RWRoOhk5Y1srHHwV3nKshZ5ED0tb/LquP31iBGy0VncHiUiS4LgXqJ1YrARHdm/mI+SR
z8J/t3L4/5p8qflst/lPpkgT6B2o1UTjShI+1+7t3JCAHWRRX5NQQxE2OxK3kRIh+xiZx2
jT1mUWssDfkieX5uJ6AVEM6Iu0C/Wy0YxCZX9NqZUgsFNf3HyYPvMlyg+ujowAReMmpXGg
mC+hcIFQ/o/rDkyfzUx0ZdVErAoTCSSeAjopqnXQ2JeDOJvYG2L49L0oqnDtoAuNCAhCx7
usg0PimqlwDmQQM=
-----END SSH SIGNATURE-----
remaining`

	sig, rest, err := sshsign.UnmarshalArmoured([]byte(armoured))
	require.NoError(t, err, "no error should be returned when unmarshalling")
	assert.Equal(t, string(rest), "remaining", "the rest of the signature should be returned")
	assert.Equal(t, sig.Version, uint32(1), "version should be 1")
	assert.Equal(t, sig.Namespace, "file", "namespace should be 'file'")
	assert.Equal(t, sig.HashAlgorithm, "sha512", "hash algorithm should be 'rsa-sha2-256'")

	rearmoured, err := sig.MarshalArmoured()
	require.NoError(t, err, "marhsalling should not generate an error")

	assertArmouredEqual(t, []byte(armoured), []byte(rearmoured))
}

func assertArmouredEqual(t *testing.T, d1, d2 []byte) {
	b1, _ := pem.Decode(d1)
	b2, _ := pem.Decode(d2)

	assert.Equal(t, b1.Type, b2.Type, "both armoured sections should have the same type")
	assert.Equal(t, b1.Headers, b2.Headers, "both armoured sections should have the same headers")
	assert.Equal(t, base64.RawStdEncoding.EncodeToString(b1.Bytes), base64.RawStdEncoding.EncodeToString(b2.Bytes), "both armoured sections should have the same bytes")
}
