package sshbuf_test

import (
	"testing"

	"github.com/SierraSoftworks/sshsign-go/internal/sshbuf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNumbers(t *testing.T) {
	b := new(sshbuf.Buffer)
	require.NoError(t, b.WriteUint32(0x12345678))
	assert.Equal(t, b.Len(), 4)
	assert.Equal(t, b.Bytes(), []byte{0x12, 0x34, 0x56, 0x78})

	n, err := b.ReadUint32()
	require.NoError(t, err)
	assert.Equal(t, n, uint32(0x12345678))
}
