//Tests TMSP, note more specific scenarios for broadcast are tested in ui_test.go
package tmsp

import (
	"sync"
	"testing"

	cmn "github.com/rigelrozanski/passwerk/common"
)

func TestUi(t *testing.T) {

	//inititilize DB for testing
	err, stateHashKeyIn, pwkDBIn, _, stateIn, _ := cmn.InitTestingDB()

	if err != nil {
		t.Errorf(err.Error())
	}

	//remove the testing db before exit
	defer func() {
		err = cmn.DeleteTestingDB(pwkDBIn)

		if err != nil {
			t.Errorf("err deleting testing DB: ", err.Error())
		}
	}()

	//lock for data access, unused for testing purposes
	var muTest = &sync.Mutex{}

	/////////////////////////////
	// Perform a test broadcast
	urlStringBytes := []byte("w/masterU/masterP/testID/testPass")

	//note more specific scenarios of broadcast are tested as a part of ui_test.go
	TestspoofBroadcast(urlStringBytes, muTest, stateIn, pwkDBIn, stateHashKeyIn, 0)

	if err != nil {
		t.Errorf(err.Error())
	}

}
