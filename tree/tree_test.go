//This package tests the tree package

package tree

import (
	//	"errors"
	"path"
	"sync"
	"testing"

	cry "github.com/rigelrozanski/passwerk/crypto"
)

func TestTree(t *testing.T) {

	//inititilize DB for testing
	pwkDb, ptw, ptr, err := InitTestingDB()

	testErrBasic := func(errIn error) {
		if errIn != nil {
			t.Errorf(errIn.Error())
		}
	}

	testErrBasic(err)

	//remove the testing db before exit
	defer func() {
		err = DeleteTestingDB(pwkDb)

		if err != nil {
			t.Errorf("err deleting testing DB: ", err.Error())
		}
	}()

	//lock for data access, unused for testing purposes
	muTest := new(sync.Mutex)
	muTest.Lock()

	//////////////////////////////////////////////////////
	//functions for defining new readers and writers

	//define the passwerk tree reader
	updatePTR := func(urlUsername, urlPassword, urlCIdName string) {

		hashInputCIdNameEncryption := path.Join(urlUsername, urlPassword)
		hashInputCPasswordEncryption := path.Join(urlCIdName, urlPassword, urlUsername)
		usernameHashed := cry.GetHashedHexString(urlUsername)
		passwordHashed := cry.GetHashedHexString(urlPassword)

		ptr.SetVariables(
			usernameHashed,
			passwordHashed,
			urlCIdName,
			hashInputCIdNameEncryption,
			hashInputCPasswordEncryption,
		)
	}

	//define the passwerk tree writer
	// -the forDeleting term specifies if the ptw will be used for deleting as opposed to writing
	updatePTW := func(forDeleting bool, urlUsername, urlPassword, urlCIdName string) (err error) {

		hashInputCIdNameEncryption := path.Join(urlUsername, urlPassword)
		usernameHashed := cry.GetHashedHexString(urlUsername)
		passwordHashed := cry.GetHashedHexString(urlPassword)
		cIdNameHashed := cry.GetHashedHexString(urlCIdName)

		var encryptedCIdName string
		if forDeleting {
			updatePTR(urlUsername, urlPassword, urlCIdName)
			encryptedCIdName, err = ptr.GetCIdListEncryptedCIdName()
		} else {
			encryptedCIdName = cry.GetEncryptedHexString(hashInputCIdNameEncryption, urlCIdName)
		}

		ptw.SetVariables(
			usernameHashed,
			passwordHashed,
			cIdNameHashed,
			encryptedCIdName,
		)

		return
	}

	getEncryptedCPassword := func(urlUsername, urlPassword, urlCIdName, urlCPassword string) string {
		hashInputCPasswordEncryption := path.Join(urlCIdName, urlPassword, urlUsername)
		return cry.GetEncryptedHexString(hashInputCPasswordEncryption, urlCPassword)
	}

	//////////////////////////////////////////////////////////
	//perform the actual tests

	//func (ptw *PwkTreeWriter) DeleteRecord() (err error) {
	//func (ptw *PwkTreeWriter) NewRecord(cPasswordEncrypted string) (err error) {
	//func (ptr *PwkTreeReader) Authenticate() bool {
	//func (ptr *PwkTreeReader) RetrieveCIdNames() (cIdNames []string, err error) {
	//func (ptr *PwkTreeReader) RetrieveCPassword() (cPassword string, err error) {

	mUsr := "masterUsr"
	mPwd := "masterPwd"
	cId := []string{"savedName1", "savedName2"}
	cPwd := []string{"savedPass1", "savedPass2"}

	//create two new records
	testErrBasic(updatePTW(false, mUsr, mPwd, cId[0]))
	enPass1 := getEncryptedCPassword(mUsr, mPwd, cId[0], cPwd[0])
	ptw.NewRecord(enPass1)

	testErrBasic(updatePTW(false, mUsr, mPwd, cId[1]))
	enPass2 := getEncryptedCPassword(mUsr, mPwd, cId[1], cPwd[1])
	ptw.NewRecord(enPass2)

	//authenticate
	updatePTR(mUsr, mPwd, cId[0])
	if !ptr.Authenticate() {
		t.Errorf("bad authentication when expected good authentication")
	}

	//retrieve list
	cIdNames, err1 := ptr.RetrieveCIdNames()
	testErrBasic(err1)

	//note that the list begins and ends with a blank record, so the size must be at least 4 if there are two records held
	if len(cIdNames) < 4 {
		t.Errorf("unexpected number of records in cIdNames retrieval")
	} else {
		if (cIdNames[1]) != cId[0] {
			t.Errorf("in the cIdName List got " + cIdNames[1] + " but expected " + cId[0])
		}
		if (cIdNames[2]) != cId[1] {
			t.Errorf("in the cIdName List got " + cIdNames[2] + " but expected " + cId[1])
		}
	}

	//retrieve a cPassword
	cPassword, err2 := ptr.RetrieveCPassword()
	testErrBasic(err2)
	if cPassword != cPwd[0] {
		t.Errorf("bad password retrieve got " + cPassword + " but expected " + cPwd[0])
	}

	//bad retrieve a cPassword
	updatePTR(mUsr, mPwd, "garbullygoop")
	_, err3 := ptr.RetrieveCPassword()
	if err3 == nil {
		t.Errorf("bad password retrieval does not produce an expected error")
	}

	//open a bad ptw (aka if attempting to perform a bad delete)
	testErrBasic(updatePTW(true, mUsr, mPwd, "garbullyGoop"))
	err4 := ptw.DeleteRecord()
	if err4 == nil {
		t.Errorf("bad PTW does not produce error")
	}

	//delete the two records
	testErrBasic(updatePTW(true, mUsr, mPwd, cId[0]))
	testErrBasic(ptw.DeleteRecord())
	testErrBasic(updatePTW(true, mUsr, mPwd, cId[1]))
	testErrBasic(ptw.DeleteRecord())

	//authenticate, but should be denied because user has all records deleted
	updatePTR(mUsr, mPwd, cId[0])
	if ptr.Authenticate() {
		t.Errorf("good authentication when expected bad authentication")
	}

}
