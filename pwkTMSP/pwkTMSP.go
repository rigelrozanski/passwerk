//This package is charged with communication with tendermint-core
package pwkTMSP

import (
	"strings"

	tree "passwerk/treeMgt"

	. "github.com/tendermint/go-common"
	"github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
	"github.com/tendermint/tmsp/types"
)

type PasswerkApplication struct {
	state        merkle.Tree
	stateDB      db.DB
	stateHashKey []byte
}

func NewPasswerkApplication(stateIn merkle.Tree, stateDBIn db.DB, stateHashKeyIn []byte) *PasswerkApplication {

	app := &PasswerkApplication{
		state:        stateIn,
		stateDB:      stateDBIn,
		stateHashKey: stateHashKeyIn,
	}

	return app
}

//returns the size of the tx
func (app *PasswerkApplication) Info() string {
	return Fmt("size:%v", app.state.Size())
}

//SetOption is currently unsupported
func (app *PasswerkApplication) SetOption(key, value string) (log string) {
	return ""
}

//Because the tx is saved in the mempool, all tx items passed to AppendTx have already been Hashed/Encrypted
func (app *PasswerkApplication) AppendTx(tx []byte) types.Result {

	//perform a CheckTx to prevent tx errors
	checkTxResult := app.CheckTx(tx)
	if checkTxResult.IsErr() {
		return checkTxResult
	}

	//seperate the tx into all the parts to be written
	parts := strings.Split(string(tx), "/")

	//The number of parts in the TX are verified upstream within CheckTx
	operationalOption := parts[1] //part[0] contains the timeStamp which is currently ignored (used to avoid duplicate tx submissions)

	switch operationalOption {
	case "writing":
		err := tree.NewRecord(
			&app.stateDB,
			app.state,
			parts[2], //usernameHashed
			parts[3], //passwordashed
			parts[4], //cIdNameHashed
			parts[5], //cIdNameEncrypted
			parts[6], //cPasswordEncryptedi
		)
		if err != nil {
			return badReturn(err.Error())
		}
	case "deleting":
		err := tree.DeleteRecord(
			&app.stateDB,
			app.state,
			parts[2], //usernameHashed
			parts[3], //passwordHashed
			parts[4], //cIdNameHashed
			parts[5], //cIdNameEncrypted
		)
		if err != nil {
			return badReturn(err.Error())
		}

	}

	//save the momma-merkle state in the db for persistence
	app.stateDB.Set(app.stateHashKey, app.state.Save())

	return types.OK
}

//transaction logic is verfied upstream of CheckTx within InputHandler
//note that unlike a cryptocurrency implementation of tendermint
//     there are no situations equivanent to checking for double
//     spending coin. this type of verification may normally
//     need to be implemented within the CheckTx method (?).
//     There may eventually be a need to be simular logic here
//     as passwerk applications change but under the current system
//     there are no forseen circumstances in which there will be a
//     conflict if any two transactions are submitted simultaniously
//     from multiple users on the same system.
func (app *PasswerkApplication) CheckTx(tx []byte) types.Result {

	//seperate the tx into all the parts to be written
	parts := strings.Split(string(tx), "/")

	if len(parts) < 2 {
		return badReturn("Invalid number of TX parts")
	}

	operationalOption := parts[1] //part[0] contains the timeStamp which is currently ignored (used to avoid duplicate tx submissions)

	switch operationalOption {
	case "writing":
		if len(parts) < 7 {
			return badReturn("Invalid number of TX parts")
		}
	case "deleting":
		if len(parts) < 6 {
			return badReturn("Invalid number of TX parts")
		}

		usernameHashed := parts[2]
		passwordHashed := parts[3]
		cIdNameHashed := parts[4]
		cIdNameEncrypted := parts[5]

		subTree, err := tree.LoadSubTree(&app.stateDB, app.state, usernameHashed, passwordHashed)
		if err != nil {
			return badReturn("bad sub tree")
		}

		treeRecordExists := subTree.Has(tree.GetRecordKey(usernameHashed, passwordHashed, cIdNameHashed))
		_, mapValues, mapExists := subTree.Get(tree.GetIdListKey(usernameHashed, passwordHashed))
		containsCIdNameEncrypted := strings.Contains(string(mapValues), "/"+cIdNameEncrypted+"/")

		//check to make sure the record exists to be deleted
		if treeRecordExists == false ||
			mapExists == false ||
			containsCIdNameEncrypted == false {
			return badReturn("Record to delete does not exist")
		}

	default:
		return badReturn("Invalid operational option")
	}

	return types.OK
}

//return the hash of the merkle tree
func (app *PasswerkApplication) Commit() types.Result {
	return types.NewResultOK(app.state.Hash(), "")
}

//currently Query is unsupported but arguably should be supported for reading_IdNames and reading_Password values for operationalOptions
func (app *PasswerkApplication) Query(query []byte) types.Result {
	return types.NewResultOK(nil, Fmt("Query is not supported"))
}

func badReturn(log string) types.Result {
	return types.Result{
		Code: types.CodeType_BadNonce,
		Data: nil,
		Log:  Fmt(log),
	}
}
