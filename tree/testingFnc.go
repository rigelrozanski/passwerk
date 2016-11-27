//This package is only used for testing to inilitize and delete the testing database
package tree

import (
	"errors"
	//"path"
	"sync"

	cmn "github.com/rigelrozanski/passwerk/common"
	dbm "github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
)

var dBTestName string = "pwkTestDb"

func InitTestingDB() (pwkDb dbm.DB, ptw PwkTreeWriter, ptr PwkTreeReader, err error) {

	//setup the persistent merkle tree to be used by both the UI and TMSP
	oldDBNotPresent, _ := cmn.IsDirEmpty(dBTestName + "/" + dBTestName + ".db")

	if !oldDBNotPresent {
		err = errors.New("can't properly initilization of testing dbs and merkle trees")
		return
	}

	pwkDb = dbm.NewDB(dBTestName, dbm.DBBackendLevelDB, dBTestName) //open the db, if the db doesn't exist it will be created
	tree := merkle.NewIAVLTree(0, pwkDb)

	//for WAL subdirectory version
	//tree := merkle.NewIAVLTree(0, path.Join(dBTestName, cmn.WalSubDir), pwkDb)

	//set and load the merkle state
	dBKeyMerkleHash := []byte(cmn.DBKeyMerkleHash) //Keyz for db values which hold information which isn't the contents of a Merkle tree
	pwkDb.Set(dBKeyMerkleHash, tree.Save())
	tree.Load(pwkDb.Get([]byte(dBKeyMerkleHash)))

	pwkTree := NewPwkMerkleTree(tree, 0, pwkDb, dBTestName)

	var pR TreeReading = pwkTree
	var pW TreeWriting = pwkTree

	//define the readers and writers for UI and TMSP respectively
	mtx := new(sync.Mutex)                          //lock for data access
	ptr = NewPwkTreeReader(mtx, pR, "", "", "", "") //initilize blank reader variables, updated in UI
	ptw = NewPwkTreeWriter(mtx, pW, "", "", "")     //initilize blank reader variables, updated in TMSP

	return
}

func DeleteTestingDB(pwkDb dbm.DB) (err error) {
	pwkDb.Close()
	err = cmn.DeleteDir(dBTestName)
	return
}
