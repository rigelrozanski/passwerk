//This package is charged managment of the Merkle-Tree and Sub-Trees
package treeMgt

import (
	"errors"
	"fmt"
	"path"
	"strings"

	cry "passwerk/cryptoMgt"

	"github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
)

//to prevent key-value collisions in the database that holds
//  records for both the momma-tree and sub-trees, prefixes
//  are added to the keys of all the merkleTree Records
//  For the sub tree values, there is an additional prefix
//  of the hex-string of the hash of username/password
const treeKeyPrefix4SubTree string = "S"
const treeKeyPrefix4SubTreeValue string = "V"
const merkleCacheSize int = 0

///////////////////////////
/// Merkle Key Retrieval
//////////////////////////

func GetMapKey(usernameHashed, passwordHashed string) []byte {
	return []byte(path.Join(treeKeyPrefix4SubTree, usernameHashed, passwordHashed))
}

func GetIdListKey(usernameHashed, passwordHashed string) []byte {
	return []byte(path.Join(treeKeyPrefix4SubTreeValue, usernameHashed, passwordHashed))
}
func GetRecordKey(usernameHashed, passwordHashed, cIdNameHashed string) []byte {
	return []byte(path.Join(treeKeyPrefix4SubTreeValue, usernameHashed, passwordHashed, cIdNameHashed))
}

///////////////////////////
/// Sub Tree Managment
//////////////////////////

//the momma merkle tree has sub-merkle tree state (output for .Save())
// stored as the value in the key-value pair in the momma tree
func LoadSubTree(dbIn *db.DB, mommaTree merkle.Tree, usernameHashed, passwordHashed string) (merkle.Tree, error) {

	subTree := merkle.NewIAVLTree(merkleCacheSize, *dbIn)
	_, treeOutHash2Load, exists := mommaTree.Get(GetMapKey(usernameHashed, passwordHashed))
	if exists == false {
		return nil, errors.New("sub tree doesn't exist")
	}

	subTree.Load(treeOutHash2Load)

	return subTree, nil
}

func SaveSubTree(subTree, mommaTree merkle.Tree, usernameHashed, passwordHashed string) {
	mommaTree.Set(GetMapKey(usernameHashed, passwordHashed), subTree.Save())
}

func NewSubTree(dbIn *db.DB, mommaTree merkle.Tree, usernameHashed, passwordHashed string) merkle.Tree {
	subTree := merkle.NewIAVLTree(merkleCacheSize, *dbIn)
	mommaTree.Set(GetMapKey(usernameHashed, passwordHashed), subTree.Save())
	return subTree
}

///////////////////////////
/// Core Functions
//////////////////////////

func Authenticate(state merkle.Tree, usernameHashed, passwordHashed string) bool {
	mapKey := GetMapKey(usernameHashed, passwordHashed)
	return state.Has(mapKey)
}

func RetrieveCIdNames(dbIn *db.DB, state merkle.Tree, usernameHashed, passwordHashed,
	hashInputCIdNameEncryption string) (cIdNamesEncrypted []string, err error) {

	subTree, err := LoadSubTree(dbIn, state, usernameHashed, passwordHashed)

	cIdListKey := GetIdListKey(usernameHashed, passwordHashed)
	if subTree.Has(cIdListKey) {
		_, mapValues, _ := subTree.Get(cIdListKey)

		//get the encrypted cIdNames
		cIdNames := strings.Split(string(mapValues), "/")

		//decrypt the cIdNames
		for i := 0; i < len(cIdNames); i++ {
			if len(cIdNames[i]) < 1 {
				continue
			}
			cIdNames[i], err = cry.ReadDecrypted(hashInputCIdNameEncryption, cIdNames[i])
		}
		return cIdNames, err
	} else {
		err = errors.New("badAuthentication")
		return nil, err
	}
}

func RetrieveCPassword(dbIn *db.DB, state merkle.Tree, usernameHashed, passwordHashed, cIdNameHashed,
	hashInputCPasswordEncryption string) (cPassword string, err error) {

	subTree, err := LoadSubTree(dbIn, state, usernameHashed, passwordHashed)

	cPasswordKey := GetRecordKey(usernameHashed, passwordHashed, cIdNameHashed)
	_, cPasswordEncrypted, exists := subTree.Get(cPasswordKey)
	if exists {
		cPassword, err = cry.ReadDecrypted(hashInputCPasswordEncryption, string(cPasswordEncrypted))
		return
	} else {
		err = errors.New("invalidCIdName")
		return
	}
}

func DeleteRecord(dbIn *db.DB, state merkle.Tree, usernameHashed, passwordHashed, cIdNameHashed,
	cIdNameEncrypted string) (err error) {

	var subTree merkle.Tree

	subTree, err = LoadSubTree(dbIn, state, usernameHashed, passwordHashed)

	//verify the record exists
	merkleRecordKey := GetRecordKey(usernameHashed, passwordHashed, cIdNameHashed)
	cIdListKey := GetIdListKey(usernameHashed, passwordHashed)
	_, cIdListValues, cIdListExists := subTree.Get(cIdListKey)

	if subTree.Has(merkleRecordKey) == false ||
		cIdListExists == false {
		err = errors.New("record to delete doesn't exist")
		return
	}

	//delete the main record from the merkle tree
	_, successfulRemove := subTree.Remove(merkleRecordKey)
	if successfulRemove == false {
		err = errors.New("error deleting the record from subTree")
		return
	}

	//delete the index from the cIdName list
	oldCIdListValues := string(cIdListValues)
	newCIdListValues := strings.Replace(oldCIdListValues, "/"+cIdNameEncrypted+"/", "/", 1)
	subTree.Set(cIdListKey, []byte(newCIdListValues))

	//save the subTree
	SaveSubTree(subTree, state, usernameHashed, passwordHashed)

	//If there are no more values within the CIdList, then delete the CIdList
	//   as well as the main username password sub tree
	_, cIdListValues, _ = subTree.Get(cIdListKey)
	if len(string(cIdListValues)) < 2 {
		subTree.Remove(cIdListKey)
		state.Remove(GetMapKey(usernameHashed, passwordHashed))
	}

	return
}

func GetCIdListEncryptedCIdName(dbIn *db.DB, state merkle.Tree, usernameHashed, passwordHashed, cIdNameUnencrypted,
	hashInputCIdNameEncryption string) (cIdNameOrigEncrypted string, err error) {

	var subTree merkle.Tree
	subTree, err = LoadSubTree(dbIn, state, usernameHashed, passwordHashed)
	if err != nil {
		return
	}

	cIdListKey := GetIdListKey(usernameHashed, passwordHashed)
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
		tempCIdNameDecrypted, err = cry.ReadDecrypted(hashInputCIdNameEncryption, cIdNames[i])

		//remove record from master list and merkle tree
		if cIdNameUnencrypted == tempCIdNameDecrypted {
			cIdNameOrigEncrypted = cIdNames[i]
		}
	}

	return
}

//must delete any records with the same cIdName before adding a new record
func NewRecord(dbIn *db.DB, state merkle.Tree, usernameHashed, passwordHashed, cIdNameHashed,
	cIdNameEncrypted, cPasswordEncrypted string) (err error) {

	var subTree merkle.Tree

	mapKey := GetMapKey(usernameHashed, passwordHashed)
	cIdListKey := GetIdListKey(usernameHashed, passwordHashed)

	//if the relavant subTree does not exist
	//  create the subtree as well as the cIdList
	if state.Has(mapKey) {
		subTree, err = LoadSubTree(dbIn, state, usernameHashed, passwordHashed)
		if err != nil {
			fmt.Println(err)
			return
		}
		_, cIdListValues, _ := subTree.Get(cIdListKey)
		subTree.Set(cIdListKey, []byte(string(cIdListValues)+cIdNameEncrypted+"/"))

	} else {
		subTree = NewSubTree(dbIn, state, usernameHashed, passwordHashed)
		subTree.Set(cIdListKey, []byte("/"+cIdNameEncrypted+"/"))
	}

	//create the new record in the tree
	insertKey := GetRecordKey(usernameHashed, passwordHashed, cIdNameHashed)
	insertValues := []byte(cPasswordEncrypted)
	subTree.Set(insertKey, insertValues)

	SaveSubTree(subTree, state, usernameHashed, passwordHashed)

	//fmt.Println("state num records: " + strconv.Itoa(state.Size()))
	//fmt.Println("subTree num records: " + strconv.Itoa(subTree.Size()))

	return
}
