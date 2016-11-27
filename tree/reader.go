package tree

import (
	"errors"
	"strings"

	cry "github.com/rigelrozanski/passwerk/crypto"
)

type PwkTreeReader struct {
	tree TreeReading
	rVar ReaderVariables
}

type ReaderVariables struct {
	usernameHashed               string
	cIdNameUnencrypted           string
	hashInputCIdNameEncryption   string
	hashInputCPasswordEncryption string
}

func NewPwkTreeReader(
	tree TreeReading,
	usernameHashed string,
	cIdNameUnencrypted string,
	hashInputCIdNameEncryption string,
	hashInputCPasswordEncryption string) PwkTreeReader {

	rVar := ReaderVariables{
		usernameHashed:               usernameHashed,
		cIdNameUnencrypted:           cIdNameUnencrypted,
		hashInputCIdNameEncryption:   hashInputCIdNameEncryption,
		hashInputCPasswordEncryption: hashInputCPasswordEncryption,
	}

	return PwkTreeReader{
		tree: tree,
		rVar: rVar,
	}
}

func (ptr *PwkTreeReader) SetVariables(
	usernameHashed,
	cIdNameUnencrypted,
	hashInputCIdNameEncryption,
	hashInputCPasswordEncryption string) {

	ptr.rVar = ReaderVariables{
		usernameHashed:               usernameHashed,
		cIdNameUnencrypted:           cIdNameUnencrypted,
		hashInputCIdNameEncryption:   hashInputCIdNameEncryption,
		hashInputCPasswordEncryption: hashInputCPasswordEncryption,
	}
}

/////////////////////////////////////////////
//   Subtree Management
////////////////////////////////////////////

func (ptr *PwkTreeReader) loadSubTree() (TreeReading, error) {
	subTree, err := ptr.tree.LoadSubTree(ptr.rVar.usernameHashed)

	var outTree TreeReading = subTree
	return outTree, err
}

/////////////////////////////
// Main Functions
/////////////////////////////

//authenticate the master password if
func (ptr *PwkTreeReader) AuthMasterPassword() bool {

	//first check if the username exists
	if !ptr.tree.Has(getMapKey(ptr.rVar.usernameHashed)) {
		return false
	}

	_, err := ptr.RetrieveCIdNames()
	if err != nil {
		return false
	}
	return true
}

//retrieve and decrypt the list of saved passwords under and account
func (ptr *PwkTreeReader) RetrieveCIdNames() (cIdNames []string, err error) {

	var subTree TreeReading
	subTree, err = ptr.loadSubTree()

	if err != nil {
		return
	}

	cIdListKey := GetCIdListKey(ptr.rVar.usernameHashed)
	if subTree.Has(cIdListKey) {
		_, mapValues, _ := subTree.Get(cIdListKey)

		//get the encrypted cIdNames
		cIdNames = strings.Split(string(mapValues), "/")

		//decrypt the cIdNames
		for i := 0; i < len(cIdNames); i++ {

			if len(cIdNames[i]) < 1 {
				continue
			}
			cIdNames[i], err = cry.ReadDecrypted(ptr.rVar.hashInputCIdNameEncryption, cIdNames[i])
		}
		return
	} else {
		err = errors.New("badAuthentication")
		return
	}
}

//retrieve and decrypt a saved password given an account and id information
func (ptr *PwkTreeReader) RetrieveCPassword() (cPassword string, err error) {

	var subTree TreeReading
	subTree, err = ptr.loadSubTree()

	if err != nil {
		return
	}

	cPasswordKey := GetRecordKey(ptr.rVar.usernameHashed, cry.GetHashedHexString(ptr.rVar.cIdNameUnencrypted))
	if subTree.Has(cPasswordKey) {
		_, cPasswordEncrypted, _ := subTree.Get(cPasswordKey)
		cPassword, err = cry.ReadDecrypted(ptr.rVar.hashInputCPasswordEncryption, string(cPasswordEncrypted))
		return
	} else {
		err = errors.New("invalidCIdName")
		return
	}
}

// retrieve the original encrypted id text, used for deleting from the stored list of ids for a user
func (ptr *PwkTreeReader) GetCIdListEncryptedCIdName() (cIdNameOrigEncrypted string, err error) {

	var subTree TreeReading
	subTree, err = ptr.loadSubTree()

	if err != nil {
		return
	}

	cIdListKey := GetCIdListKey(ptr.rVar.usernameHashed)
	_, cIdListValues, exists := subTree.Get(cIdListKey)

	if exists == false {
		err = errors.New("sub tree doesn't exist")
		return
	}

	//get the encrypted cIdNames
	cIdNames := strings.Split(string(cIdListValues), "/")

	//determine the correct value from the cIdNames array and return
	for i := 0; i < len(cIdNames); i++ {
		if len(cIdNames[i]) < 1 {
			continue
		}
		var tempCIdNameDecrypted string
		tempCIdNameDecrypted, err = cry.ReadDecrypted(ptr.rVar.hashInputCIdNameEncryption, cIdNames[i])

		//remove record from master list and merkle.Tree
		if ptr.rVar.cIdNameUnencrypted == tempCIdNameDecrypted {
			cIdNameOrigEncrypted = cIdNames[i]
		}
	}

	return
}
