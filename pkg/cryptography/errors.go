package cryptography

import (
	"fmt"
)

type EncryptionError struct {
	message string
	err     string
}

func (e *EncryptionError) Error() string {
	return fmt.Sprintf("%s - %s", e.message, e.err)
}

func NewEncryptionKeyGenerationError(err error) error {
	return &EncryptionError{
		message: "error generating encryption key",
		err:     err.Error(),
	}
}

func NewAesBlockCreationError(err error) error {
	return &EncryptionError{
		message: "error creating aes block cipher",
		err:     err.Error(),
	}
}

func NewSettingGcmModeError(err error) error {
	return &EncryptionError{
		message: "error setting gcm mode",
		err:     err.Error(),
	}
}

func NewNonceGenerationError(err error) error {
	return &EncryptionError{
		message: "error generating the nonce",
		err:     err.Error(),
	}
}

func NewHexDecodingError(err error) error {
	return &EncryptionError{
		message: "error decoding hex",
		err:     err.Error(),
	}
}

func NewDataDecryptionError(err error) error {
	return &EncryptionError{
		message: "error decryption data",
		err:     err.Error(),
	}
}
