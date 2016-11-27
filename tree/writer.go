package tree

import (
	"errors"
	"fmt"
	"strings"
	"sync"
)

type PwkTreeWriter struct {
	mtx  *sync.Mutex
	tree TreeWriting
	wVar WritingVariables
}

type WritingVariables struct {
	usernameHashed   string
	cIdNameHashed    string
	cIdNameEncrypted string
}

func NewPwkTreeWriter(
	mtx *sync.Mutex,
	tree TreeWriting,
	usernameHashed,
	cIdNameHashed,
	cIdNameEncrypted string) PwkTreeWriter {

	wVar := WritingVariables{
		usernameHashed:   usernameHashed,
		cIdNameHashed:    cIdNameHashed,
		cIdNameEncrypted: cIdNameEncrypted,
	}

	return PwkTreeWriter{
		mtx:  mtx,
		tree: tree,
		wVar: wVar,
	}
}

func (ptw *PwkTreeWriter) SetVariables(
	usernameHashed,
	cIdNameHashed,
	cIdNameEncrypted string) {

	ptw.wVar = WritingVariables{
		usernameHashed:   usernameHashed,
		cIdNameHashed:    cIdNameHashed,
		cIdNameEncrypted: cIdNameEncrypted,
	}
}

/////////////////////////////////////////////
//   Subtree Management
////////////////////////////////////////////

//exported because used by CheckTx
func (ptw *PwkTreeWriter) LoadSubTree() (TreeWriting, error) {

	subTree, err := ptw.tree.LoadSubTree(ptw.wVar.usernameHashed)
	return subTree, err
}

func (ptw *PwkTreeWriter) newSubTree() TreeWriting {

	return ptw.tree.NewSubTree(ptw.wVar.usernameHashed)
}

func (ptw *PwkTreeWriter) saveSubTree(subTree TreeWriting) {

	ptw.tree.SaveSubTree(ptw.wVar.usernameHashed, subTree.(PwkMerkleTree))
}

/////////////////////////////////////////////
//   WRITE Tree Operations
////////////////////////////////////////////

func (ptw *PwkTreeWriter) SaveMommaTree() {

	ptw.mtx.Lock()
	defer ptw.mtx.Unlock()

	ptw.tree.SaveMommaTree()
}

func (ptw *PwkTreeWriter) Hash() []byte {

	ptw.mtx.Lock()
	defer ptw.mtx.Unlock()

	return ptw.tree.Hash()
}

func (ptw *PwkTreeWriter) VerifyRecordExists() (bool, error) {

	ptw.mtx.Lock()
	defer ptw.mtx.Unlock()

	subTree, err := ptw.LoadSubTree()

	if err != nil {
		return false, err
	}

	treeRecordExists := subTree.Has(GetRecordKey(ptw.wVar.usernameHashed, ptw.wVar.cIdNameHashed))
	_, mapValues, mapExists := subTree.Get(GetCIdListKey(ptw.wVar.usernameHashed))
	containsCIdNameEncrypted := strings.Contains(string(mapValues), "/"+ptw.wVar.cIdNameEncrypted+"/")

	//check to make sure the record exists to be deleted
	if !treeRecordExists ||
		!mapExists ||
		!containsCIdNameEncrypted {
		return false, nil
	}

	return true, nil
}

func (ptw *PwkTreeWriter) DeleteRecord() (err error) {

	ptw.mtx.Lock()
	defer ptw.mtx.Unlock()

	var subTree TreeWriting
	subTree, err = ptw.LoadSubTree()

	if err != nil {
		return
	}

	//verify the record exists
	merkleRecordKey := GetRecordKey(ptw.wVar.usernameHashed, ptw.wVar.cIdNameHashed)
	cIdListKey := GetCIdListKey(ptw.wVar.usernameHashed)
	_, cIdListValues, cIdListExists := subTree.Get(cIdListKey)

	if !subTree.Has(merkleRecordKey) ||
		!cIdListExists {
		err = errors.New("record to delete doesn't exist")
		return
	}

	//delete the main record from the merkle.Tree
	_, successfulRemove := subTree.Remove(merkleRecordKey)
	if !successfulRemove {
		err = errors.New("error deleting the record from subTree")
		return
	}

	//delete the index from the cIdName list
	oldCIdListValues := string(cIdListValues)
	newCIdListValues := strings.Replace(oldCIdListValues, "/"+ptw.wVar.cIdNameEncrypted+"/", "/", 1)
	subTree.Set(cIdListKey, []byte(newCIdListValues))

	//save the subTree
	ptw.saveSubTree(subTree)

	//If there are no more values within the CIdList, then delete the CIdList
	//   as well as the main username password sub tree
	_, cIdListValues, _ = subTree.Get(cIdListKey)
	if len(string(cIdListValues)) < 2 {
		subTree.Remove(cIdListKey)
		ptw.tree.Remove(getMapKey(ptw.wVar.usernameHashed))
	}

	return
}

//must delete any records with the same cIdName before adding a new record
func (ptw *PwkTreeWriter) NewRecord(cpasswordEncrypted string) (err error) {

	ptw.mtx.Lock()
	defer ptw.mtx.Unlock()

	var subTree TreeWriting
	mapKey := getMapKey(ptw.wVar.usernameHashed)
	cIdListKey := GetCIdListKey(ptw.wVar.usernameHashed)

	//if the relavant subTree does not exist
	//  create the subtree as well as the cIdList
	if ptw.tree.Has(mapKey) {
		subTree, err = ptw.LoadSubTree()
		if err != nil {
			fmt.Println(err)
			return
		}
		_, cIdListValues, _ := subTree.Get(cIdListKey)
		subTree.Set(cIdListKey, []byte(string(cIdListValues)+ptw.wVar.cIdNameEncrypted+"/"))

	} else {
		subTree = ptw.newSubTree()
		subTree.Set(cIdListKey, []byte("/"+ptw.wVar.cIdNameEncrypted+"/"))
	}

	//create the new record in the tree
	insertKey := GetRecordKey(ptw.wVar.usernameHashed, ptw.wVar.cIdNameHashed)
	insertValues := []byte(cpasswordEncrypted)
	subTree.Set(insertKey, insertValues)

	ptw.saveSubTree(subTree)

	return
}
