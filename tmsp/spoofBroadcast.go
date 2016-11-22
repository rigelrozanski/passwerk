// spoof broadcast for local use, only used during testing got ui and passwerkTMSP
package tmsp

import (
	"errors"
	"sync"

	"github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
)

//function used in UI tests, spoofs functionality of broadcast tx which tendermint normally performs during operation
func TestspoofBroadcast(tx2SpoofBroadcast []byte, muIn *sync.Mutex, stateIn merkle.Tree, stateDBIn db.DB,
	stateHashKeyIn []byte, merkleCacheSizeIn int) error {

	app := NewPasswerkApplication(muIn, stateIn, stateDBIn, stateHashKeyIn, merkleCacheSizeIn)

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
