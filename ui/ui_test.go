//Tests UI
package ui

import (
	"errors"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rigelrozanski/passwerk/tmsp"
	tre "github.com/rigelrozanski/passwerk/tree"
)

func TestUi(t *testing.T) {

	//inititilize DB for testing
	pwkDb, ptw, ptr, err := tre.InitTestingDB()

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
	muTest.Lock()

	//init a testing app stuct for the UI
	app := &UIApp{
		mu:      muTest,
		ptr:     ptr,
		portUI:  "8080",
		testing: true,
	}

	testNo := 0

	testStandard := func(url, expectedContains string) {

		testNo += 1 //used to identify which test is being run for failed tests

		pntHolder := [2]string{"", ""}

		var tx2SpoofBroadcast [2]*string

		tx2SpoofBroadcast[0] = &pntHolder[0]
		tx2SpoofBroadcast[1] = &pntHolder[1]

		testOutput := getUIoutput(app.performOperation(url, tx2SpoofBroadcast))

		//split the testOuptut to remove the header above the ascii charater which contains the raw url
		splitOutput := strings.Split(testOutput, `/||||\`) //parse by the ascii character's hair (which contains the url charcter / aka users can't enter it)
		if len(splitOutput) < 2 {
			err = errors.New("improper http output parse")
			return
		} else {
			testOutput = splitOutput[1]
		}

		//perform the spoof broadcasts
		for i := 0; i < 2; i++ {
			if len(*tx2SpoofBroadcast[i]) > 0 {

				urlStringBytes := []byte(*tx2SpoofBroadcast[i])

				muTest.Unlock()
				tmsp.TestspoofBroadcast(urlStringBytes, muTest, ptw)
				muTest.Lock()
			}
		}

		//check the output for an expected string
		if !(strings.Contains(testOutput, expectedContains)) {
			t.Errorf("test number: " + strconv.Itoa(testNo))
			t.Errorf("error expected: " + expectedContains + " recieved: " + testOutput)
		}
	}

	//Speach Bubbles responses
	sbRes := []string{
		"not enough URL arguments",     //0
		"ugh... general error",         //1
		"do i know u?",                 //2
		"sry nvr heard of it </3",      //3
		"...psst down at my toes",      //4
		"*Chuckles* - nvr heard of no", //5
		"Roger That",                   //6
	}

	read := "r"
	write := "w"
	delete := "d"

	mUsr := "masterUsr"
	mPwd := "masterPwd"
	cId := []string{"savedName1", "savedName2"}
	cPwd := []string{"savedPass1", "savedPass2"}

	//test for keyboard vomit
	testStandard("asd:SDF%$%^fgsadf", sbRes[0])

	//test for submitting a new password for a new user
	testStandard(path.Join(write, mUsr, mPwd, cId[0], cPwd[0]), sbRes[6])
	testStandard(path.Join(write, mUsr, mPwd, cId[1], cPwd[1]), sbRes[6])

	//test for invalid bad authentication
	testStandard(path.Join(read, mUsr, "masterzzzzPi", cId[0]), sbRes[2])

	//test for basic retrieval of saved list
	testStandard(path.Join(read, mUsr, mPwd), sbRes[4])
	testStandard(path.Join(read, mUsr, mPwd), cId[0])
	testStandard(path.Join(read, mUsr, mPwd), cId[1])

	//test for basic retrieval
	testStandard(path.Join(read, mUsr, mPwd, cId[0]), cPwd[0])
	testStandard(path.Join(read, mUsr, mPwd, cId[1]), cPwd[1])

	//test for invalid retrieval
	testStandard(path.Join(read, mUsr, mPwd, "sdfaasdf"), sbRes[3])

	//test for invalid deletion
	testStandard(path.Join(delete, mUsr, mPwd, "sdfaasdf"), sbRes[3])

	//test for valid deletion
	testStandard(path.Join(delete, mUsr, mPwd, cId[0]), sbRes[5])

	//test to make sure deletion actually deleted
	testStandard(path.Join(read, mUsr, mPwd, cId[0]), sbRes[3])

	//test deletion of all passwords which should also delete the user account
	testStandard(path.Join(delete, mUsr, mPwd, cId[1]), sbRes[5])

	//test that the user account has been deleted
	testStandard(path.Join(read, mUsr, mPwd), sbRes[2])
}
