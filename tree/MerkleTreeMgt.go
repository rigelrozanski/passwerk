//This package is charged managment of the Merkle-Tree and Sub-Trees
package tree

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"

	cmn "github.com/rigelrozanski/passwerk/common"
	cry "github.com/rigelrozanski/passwerk/crypto"

	"github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
)

type PwkTreeWriter struct {
	Db               db.DB
	Tree             merkle.Tree
	MerkleCacheSize  int
	UsernameHashed   string
	PasswordHashed   string
	CIdNameHashed    string
	CIdNameEncrypted string
}

type PwkTreeReader struct {
	Db                           cmn.DBReadOnly
	Tree                         cmn.MerkleTreeReadOnly
	MerkleCacheSize              int
	UsernameHashed               string
	PasswordHashed               string
	Mu                           *sync.Mutex
	CIdNameUnencrypted           string
	HashInputCIdNameEncryption   string
	HashInputCPasswordEncryption string
}

//////////////////////////////////////////
///   Merkle Key Retrieval
//////////////////////////////////////////

//to prevent key-value collisions in the database that holds
//  records for both the momma-tree and sub-trees, prefixes
//  are added to the keys of all the merkleTree Records
//  For the sub tree values, there is an additional prefix
//  of the hex-string of the hash of username/password
const keyPrefix4SubTree string = "S"
const keyPrefix4SubTreeValue string = "V"

//momma-tree key for record containing the hash for the subtree
func getMapKey(UsernameHashed, PasswordHashed string) []byte {
	return []byte(path.Join(keyPrefix4SubTree, UsernameHashed, PasswordHashed))
}

//subtree key for the record which holds the list of password identifiers (cId's)
func GetCIdListKey(UsernameHashed, PasswordHashed string) []byte {
	return []byte(path.Join(keyPrefix4SubTreeValue, UsernameHashed, PasswordHashed))
}

//subtree key for a record and password combination
func GetRecordKey(UsernameHashed, PasswordHashed, cIdNameHashed string) []byte {
	return []byte(path.Join(keyPrefix4SubTreeValue, UsernameHashed, PasswordHashed, cIdNameHashed))
}

/////////////////////////////////////////////
//   WRITE Tree Operations
////////////////////////////////////////////

func (ptw *PwkTreeWriter) DeleteRecord() (err error) {

	var subTree merkle.Tree

	subTree, err = ptw.LoadSubTreePTW()

	//verify the record exists
	merkleRecordKey := GetRecordKey(ptw.UsernameHashed, ptw.PasswordHashed, ptw.CIdNameHashed)
	cIdListKey := GetCIdListKey(ptw.UsernameHashed, ptw.PasswordHashed)
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
	ptw.saveSubTree(subTree)

	//If there are no more values within the CIdList, then delete the CIdList
	//   as well as the main username password sub tree
	_, cIdListValues, _ = subTree.Get(cIdListKey)
	if len(string(cIdListValues)) < 2 {
		subTree.Remove(cIdListKey)
		ptw.Tree.Remove(getMapKey(ptw.UsernameHashed, ptw.PasswordHashed))
	}

	return
}

//must delete any records with the same cIdName before adding a new record
func (ptw *PwkTreeWriter) NewRecord(cPasswordEncrypted string) (err error) {

	var subTree merkle.Tree

	mapKey := getMapKey(ptw.UsernameHashed, ptw.PasswordHashed)
	cIdListKey := GetCIdListKey(ptw.UsernameHashed, ptw.PasswordHashed)

	//if the relavant subTree does not exist
	//  create the subtree as well as the cIdList
	if ptw.Tree.Has(mapKey) {
		subTree, err = ptw.LoadSubTreePTW()
		if err != nil {
			fmt.Println(err)
			return
		}
		_, cIdListValues, _ := subTree.Get(cIdListKey)
		subTree.Set(cIdListKey, []byte(string(cIdListValues)+ptw.CIdNameEncrypted+"/"))

	} else {
		subTree = ptw.newSubTree()
		subTree.Set(cIdListKey, []byte("/"+ptw.CIdNameEncrypted+"/"))
	}

	//create the new record in the tree
	insertKey := GetRecordKey(ptw.UsernameHashed, ptw.PasswordHashed, ptw.CIdNameHashed)
	insertValues := []byte(cPasswordEncrypted)
	subTree.Set(insertKey, insertValues)

	ptw.saveSubTree(subTree)

	return
}

/////////////////////////////////////////////
//   READ ONLY Tree Operations
/////////////////////////////////////////////

const tempDBName string = "temp"

//authenticate that the user is in the system
func (ptr *PwkTreeReader) Authenticate() bool {
	mapKey := getMapKey(ptr.UsernameHashed, ptr.PasswordHashed)
	return ptr.Tree.Has(mapKey)
}

//retrieve and decrypte the list of saved passwords under and account
func (ptr *PwkTreeReader) RetrieveCIdNames() (cIdNames []string, err error) {

	var tempCopyDB db.DB
	tempCopyDB, err = openTempCopyDB(ptr.Db, tempDBName)

	defer func() {
		//remove the temp db
		err = deleteTempCopyDB(ptr.Db.DBPath, tempDBName, tempCopyDB)
	}()

	var subTree merkle.Tree
	subTree, err = ptr.loadSubTreePTR(tempCopyDB)

	cIdListKey := GetCIdListKey(ptr.UsernameHashed, ptr.PasswordHashed)
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

//retrieve and decrypt a saved password given an account and id information
func (ptr *PwkTreeReader) RetrieveCPassword() (cPassword string, err error) {

	//create a temp DB
	var tempCopyDB db.DB
	tempCopyDB, err = openTempCopyDB(ptr.Db, tempDBName)

	defer func() {
		//remove the temp db
		if err != nil {
			deleteTempCopyDB(ptr.Db.DBPath, tempDBName, tempCopyDB)
		} else {
			err = deleteTempCopyDB(ptr.Db.DBPath, tempDBName, tempCopyDB)
		}
	}()

	var subTree merkle.Tree
	subTree, err = ptr.loadSubTreePTR(tempCopyDB)

	cPasswordKey := GetRecordKey(ptr.UsernameHashed, ptr.PasswordHashed, cry.GetHashedHexString(ptr.CIdNameUnencrypted))
	if subTree.Has(cPasswordKey) {
		_, cPasswordEncrypted, _ := subTree.Get(cPasswordKey)
		cPassword, err = cry.ReadDecrypted(ptr.HashInputCPasswordEncryption, string(cPasswordEncrypted))
		return
	} else {
		err = errors.New("invalidCIdName")
		return
	}
}

// retrieve the original encrypted id text, used for deleting from the stored list of ids for a user
func (ptr *PwkTreeReader) GetCIdListEncryptedCIdName() (cIdNameOrigEncrypted string, err error) {

	var tempCopyDB db.DB
	tempCopyDB, err = openTempCopyDB(ptr.Db, tempDBName)

	defer func() {
		//remove the temp db
		err = deleteTempCopyDB(ptr.Db.DBPath, tempDBName, tempCopyDB)
	}()

	var subTree merkle.Tree
	subTree, err = ptr.loadSubTreePTR(tempCopyDB)

	if err != nil {
		return
	}

	cIdListKey := GetCIdListKey(ptr.UsernameHashed, ptr.PasswordHashed)
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

/////////////////////////////////////////
//   Temp DB management operations
/////////////////////////////////////////

// the following methods are used for generating temp copies of the main DB
// for reading purposes only (hence, don't modify the original DB at all
// while reading)

func openTempCopyDB(dbIn cmn.DBReadOnly, tempName string) (tempDB db.DB, err error) {

	defer func() {
		if r := recover(); r != nil {
			fmt.Println("panic while generating temp DB, retrying")

			tempDB = nil
			err = errors.New("trouble generating tempDB, please retry")
		}
	}()

	cmn.CopyDir(path.Join(dbIn.DBPath, dbIn.DBName+".db"), path.Join(dbIn.DBPath, tempName+".db"))
	tempDB = db.NewDB(tempName, db.DBBackendLevelDB, dbIn.DBPath)
	return
}

func deleteTempCopyDB(dbDir, tempName string, tempDB db.DB) error {
	tempDB.Close()
	return cmn.DeleteDir(path.Join(dbDir, tempName+".db"))
}

///////////////////////////////////////////
///    Sub Tree Managment
///////////////////////////////////////////

//the momma merkle tree has sub-merkle tree state (output for .Save())
// stored as the value in the key-value pair in the momma tree
func (ptw *PwkTreeWriter) LoadSubTreePTW() (merkle.Tree, error) {

	return loadSubTree(ptw.MerkleCacheSize,
		ptw.Db,
		ptw.Tree,
		ptw.UsernameHashed,
		ptw.PasswordHashed)
}

func (ptr *PwkTreeReader) loadSubTreePTR(dbTemp db.DB) (merkle.Tree, error) {

	return loadSubTree(ptr.MerkleCacheSize,
		dbTemp,
		ptr.Tree,
		ptr.UsernameHashed,
		ptr.PasswordHashed)
}

func loadSubTree(MerkleCacheSize int, Db db.DB, Tree cmn.MerkleTreeReadOnly,
	UsernameHashed, PasswordHashed string) (merkle.Tree, error) {

	subTree := merkle.NewIAVLTree(MerkleCacheSize, Db)
	_, treeOutHash2Load, exists := Tree.Get(getMapKey(UsernameHashed, PasswordHashed))
	if exists == false {
		return nil, errors.New("sub tree doesn't exist")
	}

	subTree.Load(treeOutHash2Load)

	return subTree, nil
}

func (ptw *PwkTreeWriter) saveSubTree(subTree merkle.Tree) {
	ptw.Tree.Set(getMapKey(ptw.UsernameHashed, ptw.PasswordHashed), subTree.Save())
}

func (ptw *PwkTreeWriter) newSubTree() merkle.Tree {

	subTree := merkle.NewIAVLTree(ptw.MerkleCacheSize, ptw.Db)
	ptw.Tree.Set(getMapKey(ptw.UsernameHashed, ptw.PasswordHashed), subTree.Save())
	return subTree
}
