//This package is charged with the user interface and functionality
package common

//////////////////////////
///  Interface & Structs
//////////////////////////

//Same as the merkle.Tree Type but without: Set, Remove, Load, Copy, Save
type MerkleTreeReadOnly interface {
	Size() (size int)
	Height() (height int8)
	Has(key []byte) (has bool)
	Get(key []byte) (index int, value []byte, exists bool)
	GetByIndex(index int) (key []byte, value []byte)
	HashWithCount() (hash []byte, count int)
	Hash() (hash []byte)
	Iterate(func(key []byte, value []byte) (stop bool)) (stopped bool)

	LoadSubTree()
}

//Same as db.DB but without: Set, SetSync, Delete, DeleteSync, Close
type DBReadOnly interface {
	Get([]byte) []byte
}

func NewDBReadOnly() *dbReadOnly {

}

type dbReadOnly struct {
	dbm.DB

	DBFile DBReadOnlyDB
	DBPath string
	DBName string
}

//----

// TODO: use this, dont pass it around
const DBKeyMerkleHash = "mommaHash"
