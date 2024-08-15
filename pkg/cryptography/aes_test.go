package cryptography_test

import (
	"testing"

	"github.com/AntonioMartinezFernandez/go-cryptography/pkg/cryptography"
	"github.com/stretchr/testify/assert"
)

func TestNew32BitsRandomKey(t *testing.T) {
	key, err := cryptography.New32BitsRandomKey()

	assert.Nil(t, err)
	assert.NotNil(t, key)
}

func TestEncodeAes256(t *testing.T) {
	data := []byte("TOP SECRET!")
	key := "H1XSCO7+LcqBFNzx2aUbzpUxbnxvoEdL"

	encoded, err := cryptography.EncodeAes256(data, []byte(key))

	assert.Nil(t, err)
	assert.NotNil(t, encoded)
	assert.Equal(t, len(*encoded), 78)
}

func TestDecodeAes256(t *testing.T) {
	data := []byte("TOP SECRET!")
	key := "H1XSCO7+LcqBFNzx2aUbzpUxbnxvoEdL"
	encoded := "41e8a918bda490c55fbc80acd8409323f7720477f5ce390b40de22d409851853a97326c8903e60"

	decoded, err := cryptography.DecodeAes256(encoded, []byte(key))

	assert.Nil(t, err)
	assert.NotNil(t, decoded)
	assert.Equal(t, *decoded, data)
}
