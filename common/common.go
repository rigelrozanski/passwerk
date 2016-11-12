//This package is charged with the user interface and functionality
package common

//////////////////////////
///  Interface & Structs
//////////////////////////

//Same as the merkle.Tree Type but without: Set, Remove, Load, Copy
type MerkleTreeReadOnly interface {
	Size() (size int)
	Height() (height int8)
	Has(key []byte) (has bool)
	Get(key []byte) (index int, value []byte, exists bool)
	GetByIndex(index int) (key []byte, value []byte)
	HashWithCount() (hash []byte, count int)
	Hash() (hash []byte)
	Save() (hash []byte)
	Iterate(func(key []byte, value []byte) (stop bool)) (stopped bool)
}

//Same as db.DB but without: Set, SetSync, Delete, DeleteSync, Close
type DBReadOnlyDB interface {
	Get([]byte) []byte
	Print()
}

type DBReadOnly struct {
	DBFile DBReadOnlyDB
	DBPath string
	DBName string
}

//////////////////////////
///  Flag Identifiers
//////////////////////////

const FlgIDMerkleCacheSize string = "merkle"  //const merkleCacheSize int = 0
const FlgIDPasswerkPort string = "pwkPort"    //const portPasswerkUI string = "8080"
const FlgIDTendermintPort string = "tmspPort" //const portTendermint string = "46657"
const FlgIDDBPath string = "dbPath"           //dbPath := "db"
const FlgIDDBName string = "dbName"           //dbName := "passwerkDB"
