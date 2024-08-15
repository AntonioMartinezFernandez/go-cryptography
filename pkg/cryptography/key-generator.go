package cryptography

import "crypto/rand"

func New32BitsRandomKey() ([]byte, error) {
	key := make([]byte, 32)

	if _, err := rand.Reader.Read(key); err != nil {
		return nil, NewEncryptionKeyGenerationError(err)
	}

	return key, nil
}
