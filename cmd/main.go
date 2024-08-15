package main

import (
	"fmt"

	cryptography "github.com/AntonioMartinezFernandez/go-cryptography/pkg/cryptography"
)

func main() {
	data := []byte("TOP SECRET!")
	key, err := cryptography.New32BitsRandomKey()
	if err != nil {
		panic(err)
	}

	encoded, err := cryptography.EncodeAes256(data, key)
	if err != nil {
		panic(err)
	}

	decoded, err := cryptography.DecodeAes256(*encoded, key)
	if err != nil {
		panic(err)
	}

	fmt.Println("original data:", string(data))
	fmt.Println("encrypted data:", *encoded)
	fmt.Println("decrypted data:", string(*decoded))
}
