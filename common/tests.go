//This package is only used for testing to inilitize and delete the testing database
package common

import (
	"errors"
	"github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
)

var dBPath string = "pwkTestDb"
var dBName string = "pwkTestDb"

// TODO: dont name this many returns, error last
func InitTestingDB() (err error, dBKeyMerkleHash []byte, pwkDB db.DB, pwkDBReadOnly DBReadOnly, state merkle.Tree, stateReadOnly MerkleTreeReadOnly) {

	//setup the persistent merkle tree to be used by both the UI and TMSP
	oldDBNotPresent, _ := IsDirEmpty(dBPath + "/" + dBName + ".db")

	if !oldDBNotPresent {
		err = errors.New("can't properly initilization of testing dbs and merkle trees")
		return
	}

	dBKeyMerkleHash = []byte("mommaHash")                 //Keyz for db values which hold information which isn't the contents of a Merkle tree
	pwkDB = db.NewDB(dBPath, db.DBBackendLevelDB, dBName) //open the db, if the db doesn't exist it will be created
	state = merkle.NewIAVLTree(0, pwkDB)

	//set and load the merkle state
	pwkDB.Set(dBKeyMerkleHash, state.Save())
	state.Load(pwkDB.Get([]byte(dBKeyMerkleHash)))

	stateReadOnly = state.(MerkleTreeReadOnly)
	pwkDBReadOnly = DBReadOnly{DBFile: pwkDB,
		DBPath: dBPath,
		DBName: dBName,
	}
	return
}

func DeleteTestingDB(pwkDB db.DB) (err error) {
	pwkDB.Close()
	err = DeleteDir(dBPath + "/" + dBName + ".db")
	return
}
