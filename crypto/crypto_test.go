//This:w package is charged with cryptographic functionality
package crypto

import (
	"testing"
)

//func ReadDecrypted(hashInput, encryptedString string) (decryptedString string, err error) {
//func GetEncryptedHexString(hashInput, unencryptedString string) string {
//func GetHashedHexString(dataInput string) string {

func TestCrypto(t *testing.T) {
	testSharedEncryptionKey := "topSecretKey"
	secretMessage := "property is theft"

	encryptedHexString := GetEncryptedHexString(testSharedEncryptionKey, secretMessage)
	decryptedHexString, err := ReadDecrypted(testSharedEncryptionKey, encryptedHexString)

	if err != nil {
		t.Errorf("err decrypting: ", err.Error())
	}

	if decryptedHexString != secretMessage {
		t.Errorf("decrypted message does not match original message")
	}

}
