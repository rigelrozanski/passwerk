package common

import (
	"os"
	"testing"
)

func TestCommon(t *testing.T) {

	//setup a new directory for testing
	testDir := "passwerkTempDir"
	testSubDir := testDir + "/subDirTest"
	testDir4Copy := "passwerkTempDir2"

	//make the test directory, will be empty
	err := os.Mkdir(testDir, 0777)
	if err != nil {
		t.Errorf("err creating dir: ", err.Error())
		err = nil
	}

	//test the empty dir
	var dirIsEmpty bool = false
	dirIsEmpty, err = IsDirEmpty(testDir)
	if err != nil {
		t.Errorf("err testing IsDirEmpty: ", err.Error())
		err = nil
	} else if !dirIsEmpty {
		t.Errorf("failed IsDirEmpty logic, empty dir considered non-empty")
	}

	//make the test sub directory
	err = os.Mkdir(testSubDir, 0777)
	if err != nil {
		t.Errorf("err creating dir: ", err.Error())
		err = nil
	}

	//test to see if testDir is still empty (shouldn't be)
	dirIsEmpty = true
	dirIsEmpty, err = IsDirEmpty(testDir)
	if err != nil {
		t.Errorf("err testing IsDirEmpty: ", err.Error())
		err = nil
	} else if dirIsEmpty {
		t.Errorf("failed IsDirEmpty logic, non-empty dir considered empty")
	}

	//test the copy directory, should copy all sub files (including the sub directory generated)
	err = CopyDir(testDir, testDir4Copy)
	if err != nil {
		t.Errorf("err copying dir: ", err.Error())
		err = nil
	}

	//test to see if was copyied
	dirIsEmpty = true
	dirIsEmpty, err = IsDirEmpty(testDir4Copy)
	if err != nil {
		t.Errorf("err testing IsDirEmpty: ", err.Error())
		err = nil
	} else if dirIsEmpty {
		t.Errorf("failed IsDirEmpty logic, non-empty dir considered empty")
	}

	//delete the testing directories
	err = DeleteDir(testDir)
	err = DeleteDir(testDir4Copy)
	if err != nil {
		t.Errorf("err deleting dir: ", err.Error())
		err = nil
	}
}
