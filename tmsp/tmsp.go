//This package is charged with communication with tendermint-core
package tmsp

import (
	"strings"

	tre "github.com/rigelrozanski/passwerk/tree"

	. "github.com/tendermint/go-common"
	"github.com/tendermint/tmsp/types"
)

type PasswerkTMSP struct {
	ptw tre.PwkTreeWriter
}

func NewPasswerkApplication(ptw tre.PwkTreeWriter) *PasswerkTMSP {
	app := &PasswerkTMSP{
		ptw: ptw,
	}
	return app
}

//Info is not supported
func (app *PasswerkTMSP) Info() string {
	return Fmt("Info not supported")
}

//SetOption is currently unsupported
func (app *PasswerkTMSP) SetOption(key, value string) (log string) {
	return ""
}

//Because the tx is saved in the mempool, all tx items passed to AppendTx have already been Hashed/Encrypted
func (app *PasswerkTMSP) AppendTx(tx []byte) types.Result {

	//perform a CheckTx to prevent tx errors
	checkTxResult := app.CheckTx(tx)
	if checkTxResult.IsErr() {
		return checkTxResult
	}

	//seperate the tx into all the parts to be written
	parts := strings.Split(string(tx), "/")

	//The number of parts in the TX are verified upstream within CheckTx
	operationalOption := parts[1] //part[0] contains the timeStamp which is currently ignored (used to avoid duplicate tx submissions)

	app.ptw.SetVariables(
		parts[2], //usernameHashed,
		parts[3], //cIdNameHashed,
		parts[4], //mapCIdNameEncrypted
	)

	switch operationalOption {
	case "writing":
		err := app.ptw.NewRecord(parts[5]) //parts[6] is cPasswordEncrypted
		if err != nil {
			return badReturn(err.Error())
		}

	case "deleting":
		err := app.ptw.DeleteRecord()
		if err != nil {
			return badReturn(err.Error())
		}
	}

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
//     from multiple uses on the same system.
func (app *PasswerkTMSP) CheckTx(tx []byte) types.Result {

	//seperate the tx into all the parts to be written
	parts := strings.Split(string(tx), "/")

	if len(parts) < 2 {
		return badReturn("Invalid number of TX parts")
	}

	operationalOption := parts[1] //part[0] contains the timeStamp which is currently ignored (used to avoid duplicate tx submissions)

	switch operationalOption {
	case "writing":
		if len(parts) < 6 {
			return badReturn("Invalid number of TX parts")
		}
		//TODO add proof-of-valid-transaction verification

	case "deleting":
		if len(parts) < 5 {
			return badReturn("Invalid number of TX parts")
		}
		//TODO add proof-of-valid-transaction verification

		app.ptw.SetVariables(parts[2], parts[3], parts[4])

		recExists, err := app.ptw.VerifyRecordExists()

		if err != nil {
			return badReturn(err.Error())
		}

		if !recExists {
			return badReturn("Record to delete does not exist")
		}

	default:
		return badReturn("Invalid operational option")
	}

	return types.OK
}

//return the hash of the merkle tree, use locks
func (app *PasswerkTMSP) Commit() types.Result {

	//save the momma-merkle state in the db for persistence
	app.ptw.SaveMommaTree()

	return types.NewResultOK(app.ptw.Hash(), "")
}

//currently Query is unsupported but arguably should be supported for reading_IdNames and reading_Password values for operationalOptions
func (app *PasswerkTMSP) Query(query []byte) types.Result {
	return types.NewResultOK(nil, Fmt("Query is not supported"))
}

func badReturn(log string) types.Result {
	return types.Result{
		Code: types.CodeType_BadNonce,
		Data: nil,
		Log:  Fmt(log),
	}
}
