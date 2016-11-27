// spoof broadcast for local use, only used during testing got ui and passwerkTMSP
package tmsp

import (
	"errors"

	tre "github.com/rigelrozanski/passwerk/tree"
)

//function used in UI tests, spoofs functionality of broadcast tx which tendermint normally performs during operation
func TestspoofBroadcast(tx2SpoofBroadcast []byte, ptw tre.PwkTreeWriter) error {

	app := NewPasswerkApplication(ptw)

	checkTxResult := app.CheckTx(tx2SpoofBroadcast)

	if checkTxResult.IsErr() {
		return errors.New(checkTxResult.Log)
	}

	appendTxResult := app.AppendTx(tx2SpoofBroadcast)

	if appendTxResult.IsErr() {
		return errors.New(appendTxResult.Log)
	}

	commitTxResult := app.Commit()

	if commitTxResult.IsErr() {
		return errors.New(commitTxResult.Log)
	}

	return nil
}
