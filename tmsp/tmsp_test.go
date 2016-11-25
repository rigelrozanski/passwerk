//Tests TMSP, note more specific scenarios for broadcast are tested in ui_test.go
package tmsp

import (
	"sync"
	"testing"

	tre "github.com/rigelrozanski/passwerk/tree"
)

func TestTMSP(t *testing.T) {

	//inititilize DB for testing
	pwkDb, ptw, _, err := tre.InitTestingDB()

	if err != nil {
		t.Errorf(err.Error())
	}

	//remove the testing db before exit
	defer func() {
		err = tre.DeleteTestingDB(pwkDb)

		if err != nil {
			t.Errorf("err deleting testing DB: ", err.Error())
		}
	}()

	//lock for data access, unused for testing purposes
	muTest := new(sync.Mutex)

	/////////////////////////////
	// Perform a test broadcast
	urlStringBytes := []byte("w/masterU/masterP/testID/testPass")

	//note more specific scenarios of broadcast are tested as a part of ui_test.go
	TestspoofBroadcast(urlStringBytes, muTest, ptw)

	if err != nil {
		t.Errorf(err.Error())
	}
}
