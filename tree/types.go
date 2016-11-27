package tree

import (
	"errors"

	cmn "github.com/rigelrozanski/passwerk/common"

	dbm "github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
)

//Ports of merkle.Tree for reading and writing
type TreeReading interface {
	Size() (size int)
	Height() (height int8)
	Has(key []byte) (has bool)
	Get(key []byte) (index int, value []byte, exists bool)
	GetByIndex(index int) (key []byte, value []byte)
	Hash() (hash []byte)

	LoadSubTree(UsernameHashed string) (PwkMerkleTree, error)
}

type TreeWriting interface {
	Size() (size int)
	Height() (height int8)
	Has(key []byte) (has bool)
	Get(key []byte) (index int, value []byte, exists bool)
	GetByIndex(index int) (key []byte, value []byte)
	Hash() (hash []byte)

	Set(key []byte, value []byte) (updated bool)
	Remove(key []byte) (value []byte, removed bool)
	Load(hash []byte)
	Save() (hash []byte)
	Copy() merkle.Tree

	LoadSubTree(UsernameHashed string) (PwkMerkleTree, error)
	NewSubTree(UsernameHashed string) PwkMerkleTree
	SaveSubTree(UsernameHashed string, subTree PwkMerkleTree)

	SaveMommaTree()
}

type PwkMerkleTree struct {
	tree      merkle.Tree
	cacheSize int
	db        dbm.DB
}

func NewPwkMerkleTree(
	tree merkle.Tree,
	cacheSize int,
	db dbm.DB) PwkMerkleTree {

	return PwkMerkleTree{
		tree:      tree,
		cacheSize: cacheSize,
		db:        db,
	}
}

///////////////////////////
//Ported Reading Functions
///////////////////////////

func (tr PwkMerkleTree) Size() (size int) {
	return tr.tree.Size()
}

func (tr PwkMerkleTree) Height() (height int8) {
	return tr.tree.Height()
}

func (tr PwkMerkleTree) Has(key []byte) (has bool) {
	return tr.tree.Has(key)
}

func (tr PwkMerkleTree) Get(key []byte) (index int, value []byte, exists bool) {
	return tr.tree.Get(key)
}

func (tr PwkMerkleTree) GetByIndex(index int) (key []byte, value []byte) {
	return tr.tree.GetByIndex(index)
}

func (tr PwkMerkleTree) Hash() (hash []byte) {
	return tr.tree.Hash()
}

///////////////////////////
//Ported Writing Functions
///////////////////////////

func (tr PwkMerkleTree) Set(key []byte, value []byte) (updated bool) {
	return tr.tree.Set(key, value)
}

func (tr PwkMerkleTree) Remove(key []byte) (value []byte, removed bool) {
	return tr.tree.Remove(key)
}

func (tr PwkMerkleTree) Load(hash []byte) {
	tr.tree.Load(hash)
}

func (tr PwkMerkleTree) Save() (hash []byte) {
	return tr.tree.Save()
}

func (tr PwkMerkleTree) Copy() merkle.Tree {
	return tr.tree.Copy()
}

/////////////////////////////////////////////
//   Subtree Management
////////////////////////////////////////////

//the momma merkle tree has sub-merkle tree state (output for .Save())
// stored as the value in the key-value pair in the momma tree
func (tr PwkMerkleTree) LoadSubTree(UsernameHashed string) (PwkMerkleTree, error) {

	subTree := merkle.NewIAVLTree(tr.cacheSize, tr.db)
	_, treeOutHash2Load, exists := tr.tree.Get(getMapKey(UsernameHashed))
	if !exists {
		return tr, errors.New("sub tree doesn't exist") //return the root tree
	}
	subTree.Load(treeOutHash2Load)

	return PwkMerkleTree{
		tree:      subTree,
		cacheSize: tr.cacheSize,
		db:        tr.db,
	}, nil
}

func (tr PwkMerkleTree) SaveSubTree(UsernameHashed string, subTree PwkMerkleTree) {
	tr.tree.Set(getMapKey(UsernameHashed), subTree.Save())
}

func (tr PwkMerkleTree) NewSubTree(UsernameHashed string) PwkMerkleTree {

	subTree := merkle.NewIAVLTree(tr.cacheSize, tr.db)
	tr.tree.Set(getMapKey(UsernameHashed), subTree.Save())

	return PwkMerkleTree{
		tree:      subTree,
		cacheSize: tr.cacheSize,
		db:        tr.db,
	}
}

func (tr PwkMerkleTree) SaveMommaTree() {
	tr.db.Set([]byte(cmn.DBKeyMerkleHash), tr.tree.Save())
}
