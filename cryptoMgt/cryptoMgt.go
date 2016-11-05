//This:w package is charged with cryptographic functionality
package cryptoMgt

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"golang.org/x/crypto/sha3"
	"io"

	"golang.org/x/crypto/nacl/box"
)

//read and decrypt from the hashPasswordList
func ReadDecrypted(hashInput, encryptedString string) (decryptedString string, err error) {

	var key [32]byte
	copy(key[:], GetHash(hashInput))

	var ciphertext, decryptedByte []byte

	ciphertext, err = hex.DecodeString(encryptedString)
	decryptedByte, err = decryptNaCl(&key, ciphertext)
	decryptedString = string(decryptedByte[:])

	return
}

//return an encrypted string. the encyption key is taken as hashed value of the input variable hashInput
func GetEncryptedHexString(hashInput, unencryptedString string) string {

	var key [32]byte
	copy(key[:], GetHash(hashInput))

	encryptedByte, err := encryptNaCl(&key, []byte(unencryptedString))

	if err == nil {
		encryptedHexString := hex.EncodeToString(encryptedByte[:])
		return encryptedHexString
	}

	return ""
}

func bytes2HexString(dataInput []byte) string {
	return hex.EncodeToString(dataInput[:])
}

//return datainput as a hex string after it has been hashed
func GetHashedHexString(dataInput string) string {

	//performing the hash
	hashBytes := GetHash(dataInput)

	//encoding to a hex string, within data the [x]byte array sliced to []byte (shorthand for h[0:len(h)])
	hashHexString := bytes2HexString(hashBytes)
	return hashHexString
}

func GetHash(dataInput string) []byte {
	//performing the hash
	hashBytes := sha3.Sum256([]byte(dataInput))
	return hashBytes[:]
}

func encryptNaCl(key *[32]byte, text []byte) (ciphertext []byte, err error) {

	var nonce [24]byte

	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return
	}

	//crypted := make([]byte, 0, box.Overhead+len(message))

	ciphertext = box.SealAfterPrecomputation([]byte(""), text, &nonce, key)
	ciphertext = append(nonce[:], ciphertext...)

	return
}

func decryptNaCl(key *[32]byte, ciphertext []byte) (plaintext []byte, err error) {

	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])

	cipherMessage := ciphertext[24:]

	plaintext, success := box.OpenAfterPrecomputation([]byte(""), cipherMessage, &nonce, key)

	if success == false {
		err = errors.New("bad decryption")
		return
	}

	return
}
