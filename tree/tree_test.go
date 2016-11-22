//This package tests the tree package

package tree

import (
	//	"errors"
	"path"
	"sync"
	"testing"

	cmn "passwerk/common"
	cry "passwerk/crypto"
)

func TestTree(t *testing.T) {

	//inititilize DB for testing
	err, _, pwkDBIn, pwkDBROIn, stateIn, stateROIn := cmn.InitTestingDB()

	testErrBasic := func(errIn error) {
		if errIn != nil {
			t.Errorf(errIn.Error())
		}
	}

	testErrBasic(err)

	//remove the testing db before exit
	defer func() {
		err = cmn.DeleteTestingDB(pwkDBIn)

		if err != nil {
			t.Errorf("err deleting testing DB: ", err.Error())
		}
	}()

	//lock for data access, unused for testing purposes
	var muTest = &sync.Mutex{}
	muTest.Lock()

	//////////////////////////////////////////////////////
	//functions for defining new readers and writers

	newPTR := func(urlUsername, urlPassword, urlCIdName string) *PwkTreeReader {
		hashInputCIdNameEncryption := path.Join(urlUsername, urlPassword)
		hashInputCPasswordEncryption := path.Join(urlCIdName, urlPassword, urlUsername)
		usernameHashed := cry.GetHashedHexString(urlUsername)
		passwordHashed := cry.GetHashedHexString(urlPassword)

		return &PwkTreeReader{
			Db:                           pwkDBROIn,
			Tree:                         stateROIn,
			MerkleCacheSize:              0,
			UsernameHashed:               usernameHashed,
			PasswordHashed:               passwordHashed,
			Mu:                           muTest,
			CIdNameUnencrypted:           urlCIdName,
			HashInputCIdNameEncryption:   hashInputCIdNameEncryption,
			HashInputCPasswordEncryption: hashInputCPasswordEncryption,
		}
	}

	//the forDeleting term specifies if the ptw will be used for deleting
	newPTW := func(forDeleting bool, urlUsername, urlPassword, urlCIdName string) (ptw *PwkTreeWriter, err error) {
		hashInputCIdNameEncryption := path.Join(urlUsername, urlPassword)
		usernameHashed := cry.GetHashedHexString(urlUsername)
		passwordHashed := cry.GetHashedHexString(urlPassword)
		cIdNameHashed := cry.GetHashedHexString(urlCIdName)

		var encryptedCIdName string
		if forDeleting {
			tempPtr := newPTR(urlUsername, urlPassword, urlCIdName)
			encryptedCIdName, err = tempPtr.GetCIdListEncryptedCIdName()
		} else {
			encryptedCIdName = cry.GetEncryptedHexString(hashInputCIdNameEncryption, urlCIdName)
		}

		ptw = &PwkTreeWriter{
			Db:               pwkDBIn,
			Tree:             stateIn,
			MerkleCacheSize:  0,
			UsernameHashed:   usernameHashed,
			PasswordHashed:   passwordHashed,
			CIdNameHashed:    cIdNameHashed,
			CIdNameEncrypted: encryptedCIdName,
		}

		return
	}

	getEncryptedCPassword := func(urlPassword, urlUsername, urlCIdName, urlCPassword string) string {
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
	enPass1 := getEncryptedCPassword(mUsr, mPwd, cId[0], cPwd[0])
	enPass2 := getEncryptedCPassword(mUsr, mPwd, cId[1], cPwd[1])
	ptw1, err := newPTW(false, mUsr, mPwd, cId[0])
	testErrBasic(err)
	ptw2, err := newPTW(false, mUsr, mPwd, cId[1])
	testErrBasic(err)

	ptw1.NewRecord(enPass1)
	ptw2.NewRecord(enPass2)

	//authenticate
	ptr1 := newPTR(mUsr, mPwd, cId[0])
	if !ptr1.Authenticate() {
		t.Errorf("bad authentication when expected good authentication")
	}

	//retrieve list
	cIdNames, err := ptr1.RetrieveCIdNames()
	testErrBasic(err)

	//note that the list begins and ends with a blank record, so the size must be at least 4 if there are two records held
	if len(cIdNames) < 4 {
		t.Errorf("unexpected number of records in cIdNames retrieval")
	} else {
		if (cIdNames[1]) != cId[0] {
			t.Errorf("in the cIdName List got " + cIdNames[1] + " but expected " + cId[0])
			//t.Errorf(cIdNames[0] + " | " + cIdNames[1] + " | " + cIdNames[2] + " | " + cIdNames[3])
		}
		if (cIdNames[2]) != cId[1] {
			t.Errorf("in the cIdName List got " + cIdNames[2] + " but expected " + cId[1])
		}
	}

	//<incomplete code> test is not working
	//retrieve a cPassword
	//cPassword, err := ptr1.RetrieveCPassword()
	//testErrBasic(err)
	//if cPassword != cPwd[0] {
	//	t.Errorf("bad password retrieve got " + cPassword + " but expected " + cPwd[0])
	//}

	//bad retrieve a cPassword
	ptr2 := newPTR(mUsr, mPwd, "garbullygoop")
	_, err = ptr2.RetrieveCPassword()
	if err == nil {
		t.Errorf("bad password retrieval does not produce an expected error")
	}
	err = nil

	//open a bad ptw (aka if attempting to perform a bad delete)
	ptwBad, err := newPTW(true, mUsr, mPwd, "garbullyGoop")
	testErrBasic(err)
	err = ptwBad.DeleteRecord()
	if err == nil {
		t.Errorf("bad PTW does not produce error")
	}

	//delete the two records
	ptw3, err := newPTW(true, mUsr, mPwd, cId[0])
	testErrBasic(err)
	ptw4, err := newPTW(true, mUsr, mPwd, cId[1])
	testErrBasic(err)
	err = ptw3.DeleteRecord()
	testErrBasic(err)
	err = ptw4.DeleteRecord()
	testErrBasic(err)

	//authenticate, but should be denied because user has all records deleted
	if ptr1.Authenticate() {
		t.Errorf("good authentication when expected bad authentication")
	}

}
