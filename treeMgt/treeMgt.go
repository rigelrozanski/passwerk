//This package is charged managment of the Merkle-Tree and Sub-Trees
package treeMgt

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"

	cmn "passwerk/common"
	cry "passwerk/cryptoMgt"

	"github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
)

//////////////////////////////////////////
///   Merkle Key Retrieval
//////////////////////////////////////////

func GetMapKey(UsernameHashed, PasswordHashed string) []byte {
	return []byte(path.Join(keyPrefix4SubTree, UsernameHashed, PasswordHashed))
}

func GetIdListKey(UsernameHashed, PasswordHashed string) []byte {
	return []byte(path.Join(keyPrefix4SubTreeValue, UsernameHashed, PasswordHashed))
}
func GetRecordKey(UsernameHashed, PasswordHashed, cIdNameHashed string) []byte {
	return []byte(path.Join(keyPrefix4SubTreeValue, UsernameHashed, PasswordHashed, cIdNameHashed))
}

/////////////////////////////////////////////
//   WRITE Tree Operations
////////////////////////////////////////////

type PwkTreeWriter struct {
	Db               db.DB
	Tree             merkle.Tree
	UsernameHashed   string
	PasswordHashed   string
	CIdNameHashed    string
	CIdNameEncrypted string
}

func (ptw *PwkTreeWriter) DeleteRecord() (err error) {

	var subTree merkle.Tree

	subTree, err = LoadSubTree(ptw.Db, ptw.Tree, ptw.UsernameHashed, ptw.PasswordHashed)

	//verify the record exists
	merkleRecordKey := GetRecordKey(ptw.UsernameHashed, ptw.PasswordHashed, ptw.CIdNameHashed)
	cIdListKey := GetIdListKey(ptw.UsernameHashed, ptw.PasswordHashed)
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
	newCIdListValues := strings.Replace(oldCIdListValues, "/"+ptw.CIdNameEncrypted+"/", "/", 1)
	subTree.Set(cIdListKey, []byte(newCIdListValues))

	//save the subTree
	SaveSubTree(subTree, ptw.Tree, ptw.UsernameHashed, ptw.PasswordHashed)

	//If there are no more values within the CIdList, then delete the CIdList
	//   as well as the main username password sub tree
	_, cIdListValues, _ = subTree.Get(cIdListKey)
	if len(string(cIdListValues)) < 2 {
		subTree.Remove(cIdListKey)
		ptw.Tree.Remove(GetMapKey(ptw.UsernameHashed, ptw.PasswordHashed))
	}

	return
}

//must delete any records with the same cIdName before adding a new record
func (ptw *PwkTreeWriter) NewRecord(cPasswordEncrypted string) (err error) {

	var subTree merkle.Tree

	mapKey := GetMapKey(ptw.UsernameHashed, ptw.PasswordHashed)
	cIdListKey := GetIdListKey(ptw.UsernameHashed, ptw.PasswordHashed)

	//if the relavant subTree does not exist
	//  create the subtree as well as the cIdList
	if ptw.Tree.Has(mapKey) {
		subTree, err = LoadSubTree(ptw.Db, ptw.Tree, ptw.UsernameHashed, ptw.PasswordHashed)
		if err != nil {
			fmt.Println(err)
			return
		}
		_, cIdListValues, _ := subTree.Get(cIdListKey)
		subTree.Set(cIdListKey, []byte(string(cIdListValues)+ptw.CIdNameEncrypted+"/"))

	} else {
		subTree = NewSubTree(ptw.Db, ptw.Tree, ptw.UsernameHashed, ptw.PasswordHashed)
		subTree.Set(cIdListKey, []byte("/"+ptw.CIdNameEncrypted+"/"))
	}

	//create the new record in the tree
	insertKey := GetRecordKey(ptw.UsernameHashed, ptw.PasswordHashed, ptw.CIdNameHashed)
	insertValues := []byte(cPasswordEncrypted)
	subTree.Set(insertKey, insertValues)

	SaveSubTree(subTree, ptw.Tree, ptw.UsernameHashed, ptw.PasswordHashed)

	return
}

/////////////////////////////////////////////
//   READ ONLY Tree Operations
/////////////////////////////////////////////

const tempDBName string = "temp"

type PwkTreeReader struct {
	Mu                           *sync.Mutex
	Db                           cmn.DBReadOnly
	Tree                         cmn.MerkleTreeReadOnly
	UsernameHashed               string
	PasswordHashed               string
	CIdNameUnencrypted           string
	HashInputCIdNameEncryption   string
	HashInputCPasswordEncryption string
}

//authenticate that the user is in the system
func (ptr *PwkTreeReader) Authenticate() bool {
	mapKey := GetMapKey(ptr.UsernameHashed, ptr.PasswordHashed)
	return ptr.Tree.Has(mapKey)
}

//retrieve and decrypte the list of saved passwords under and account
func (ptr *PwkTreeReader) RetrieveCIdNames() (cIdNames []string, err error) {

	tempCopyDB := openTempCopyDB(ptr.Mu, ptr.Db, tempDBName)

	///////////////////////////////////////////////////////////////////////////////
	main := func() {

		var subTree merkle.Tree

		subTree, err = LoadSubTree(tempCopyDB, ptr.Tree, ptr.UsernameHashed, ptr.PasswordHashed)

		cIdListKey := GetIdListKey(ptr.UsernameHashed, ptr.PasswordHashed)
		if subTree.Has(cIdListKey) {
			_, mapValues, _ := subTree.Get(cIdListKey)

			//get the encrypted cIdNames
			cIdNames = strings.Split(string(mapValues), "/")

			//decrypt the cIdNames
			for i := 0; i < len(cIdNames); i++ {

				if len(cIdNames[i]) < 1 {
					continue
				}
				cIdNames[i], err = cry.ReadDecrypted(ptr.HashInputCIdNameEncryption, cIdNames[i])
			}
			return
		} else {
			err = errors.New("badAuthentication")
			return
		}
	}
	///////////////////////////////////////////////////////////////////////////////

	main()
	if err != nil {
		return
	}

	//remove the temp db
	err = deleteTempCopyDB(ptr.Mu, ptr.Db.DBPath, tempDBName, tempCopyDB)

	return
}

//retrieve and decrypt a saved password given an account and id information
func (ptr *PwkTreeReader) RetrieveCPassword() (cPassword string, err error) {

	tempCopyDB := openTempCopyDB(ptr.Mu, ptr.Db, tempDBName)

	//////////////////////////////////////////////////////////////////////////////
	main := func() {
		var subTree merkle.Tree

		subTree, err = LoadSubTree(tempCopyDB, ptr.Tree, ptr.UsernameHashed, ptr.PasswordHashed)

		cPasswordKey := GetRecordKey(ptr.UsernameHashed, ptr.PasswordHashed, cry.GetHashedHexString(ptr.CIdNameUnencrypted))
		_, cPasswordEncrypted, exists := subTree.Get(cPasswordKey)
		if exists {
			cPassword, err = cry.ReadDecrypted(ptr.HashInputCPasswordEncryption, string(cPasswordEncrypted))
			return
		} else {
			err = errors.New("invalidCIdName")
			return
		}
	}
	//////////////////////////////////////////////////////////////////////////////

	main()
	if err != nil {
		return
	}

	//remove the temp db
	err = deleteTempCopyDB(ptr.Mu, ptr.Db.DBPath, tempDBName, tempCopyDB)

	return
}

// retrieve the original encrypted id text, used for deleting from the stored list of ids for a user
func (ptr *PwkTreeReader) GetCIdListEncryptedCIdName() (cIdNameOrigEncrypted string, err error) {

	tempCopyDB := openTempCopyDB(ptr.Mu, ptr.Db, tempDBName)

	//////////////////////////////////////////////////////////////////////////////
	main := func() {
		var subTree merkle.Tree

		subTree, err = LoadSubTree(tempCopyDB, ptr.Tree, ptr.UsernameHashed, ptr.PasswordHashed)

		if err != nil {
			return
		}

		cIdListKey := GetIdListKey(ptr.UsernameHashed, ptr.PasswordHashed)
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
			tempCIdNameDecrypted, err = cry.ReadDecrypted(ptr.HashInputCIdNameEncryption, cIdNames[i])

			//remove record from master list and merkle tree
			if ptr.CIdNameUnencrypted == tempCIdNameDecrypted {
				cIdNameOrigEncrypted = cIdNames[i]
			}
		}

		return
	}
	///////////////////////////////////////////////////////////////////////////////

	main()
	if err != nil {
		return
	}

	//remove the temp db
	err = deleteTempCopyDB(ptr.Mu, ptr.Db.DBPath, tempDBName, tempCopyDB)

	return
}

/////////////////////////////////////////
//   Temp DB management operations
/////////////////////////////////////////

// the following methods are used for generating temp copies of the main DB
// for reading purposes only (hence, don't modify the original DB at all
// while reading)

func openTempCopyDB(mu *sync.Mutex, dbIn cmn.DBReadOnly, tempName string) db.DB {

	cmn.CopyDir(path.Join(dbIn.DBPath, dbIn.DBName+".db"), path.Join(dbIn.DBPath, tempName+".db"))
	return db.NewDB(tempName, db.DBBackendLevelDB, dbIn.DBPath)
}

func deleteTempCopyDB(mu *sync.Mutex, dbDir, tempName string, tempDB db.DB) error {

	tempDB.Close()
	return cmn.DeleteDir(path.Join(dbDir, tempName+".db"))
}

///////////////////////////////////////////
///    Sub Tree Managment
///////////////////////////////////////////

//to prevent key-value collisions in the database that holds
//  records for both the momma-tree and sub-trees, prefixes
//  are added to the keys of all the merkleTree Records
//  For the sub tree values, there is an additional prefix
//  of the hex-string of the hash of username/password
const keyPrefix4SubTree string = "S"
const keyPrefix4SubTreeValue string = "V"
const merkleCacheSize int = 0

//the momma merkle tree has sub-merkle tree state (output for .Save())
// stored as the value in the key-value pair in the momma tree
func LoadSubTree(dbIn db.DB, mommaTree cmn.MerkleTreeReadOnly, UsernameHashed, PasswordHashed string) (merkle.Tree, error) {

	subTree := merkle.NewIAVLTree(merkleCacheSize, dbIn)
	_, treeOutHash2Load, exists := mommaTree.Get(GetMapKey(UsernameHashed, PasswordHashed))
	if exists == false {
		return nil, errors.New("sub tree doesn't exist")
	}

	subTree.Load(treeOutHash2Load)

	return subTree, nil
}

func SaveSubTree(subTree, mommaTree merkle.Tree, UsernameHashed, PasswordHashed string) {
	mommaTree.Set(GetMapKey(UsernameHashed, PasswordHashed), subTree.Save())
}

func NewSubTree(dbIn db.DB, mommaTree merkle.Tree, UsernameHashed, PasswordHashed string) merkle.Tree {
	subTree := merkle.NewIAVLTree(merkleCacheSize, dbIn)
	mommaTree.Set(GetMapKey(UsernameHashed, PasswordHashed), subTree.Save())
	return subTree
}
