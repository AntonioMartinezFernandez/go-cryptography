package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
)

func EncodeAes256(data []byte, key []byte) (*string, error) {
	gcm, err := newGcmAead(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, NewNonceGenerationError(err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	enc := hex.EncodeToString(ciphertext)

	return &enc, nil
}

func DecodeAes256(encodedData string, key []byte) (*[]byte, error) {
	decodedCipherText, err := hex.DecodeString(encodedData)
	if err != nil {
		return nil, NewHexDecodingError(err)
	}

	gcm, err := newGcmAead(key)
	if err != nil {
		return nil, err
	}

	decryptedData, err := gcm.Open(nil, decodedCipherText[:gcm.NonceSize()], decodedCipherText[gcm.NonceSize():], nil)
	if err != nil {
		return nil, NewDataDecryptionError(err)
	}

	return &decryptedData, nil
}

func newGcmAead(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, NewAesBlockCreationError(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, NewSettingGcmModeError(err)
	}
	return gcm, nil
}
