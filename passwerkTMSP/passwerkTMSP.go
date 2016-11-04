//    ____       _      ____    ____                 U _____ u   ____      _  __
//  U|  _"\ uU  /"\  u / __"| u/ __"| u  __        __\| ___"|/U |  _"\ u  |"|/ /
//  \| |_) |/ \/ _ \/ <\___ \/<\___ \/   \"\      /"/ |  _|"   \| |_) |/  | ' /
//   |  __/   / ___ \  u___) | u___) |   /\ \ /\ / /\ | |___    |  _ <  U/| . \\u
//   |_|     /_/   \_\ |____/>>|____/>> U  \ V  V /  U|_____|   |_| \_\   |_|\_\
//   ||>>_    \\    >>  )(  (__))(  (__).-,_\ /\ /_,-.<<   >>   //   \\_,-,>> \\,-.
//  (__)__)  (__)  (__)(__)    (__)      \_)-'  '-(_/(__) (__) (__)  (__)\.)   (_/
//
//  "A cryptographically secure password storage web-utility with distributed consensus using tendermint"

//USAGE
//
// Currently, all user input is provided through the URL.
// Within the examples HTTP calls, within the example URLs
// the following variables are described as follows:
// 	masterUsername - The master username that is non-retrievable
//      masterPassword - The master password that is non-retrievable
//      identifier - a retrievable unique identifier for a saved password
//      savedpassword - a retrievable saved password associated with an identifier
//
// EXAMPLES:
//
// writing a new record to the system:
//	http://localhost:8080/w/masterUsername/masterPassword/idenfier/savedpassword
//
// reading list of identifiers of all the saved passwords for a given master-username/master-password
//	http://localhost:8080/w/masterUsername/masterPassword/idenfier/savedpassword
//
// reading a saved password for a given master-username/master-password/identifier
//	http://localhost:8080/w/masterUsername/masterPassword/idenfier/savedpassword
//
// deleting a saved password/identifier for a given master-username/master-password/identifier
//	http://localhost:8080/w/masterUsername/masterPassword/idenfier/savedpassword
//

package passwerkTMSP

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/sha3"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	. "github.com/tendermint/go-common"
	"github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
	"github.com/tendermint/tmsp/types"
	"golang.org/x/crypto/nacl/box"
)

const portPasswerkUI string = "8080"
const portTendermint string = "46657"
const merkleCacheSize int = 0

//to prevent key-value collisions in the database that holds
//  records for both the momma-tree and sub-trees, prefixes
//  are added to the keys of all the merkleTree Records
//  For the sub tree values, there is an additional prefix
//  of the hex-string of the hash of username/password
const treeKeyPrefix4SubTree string = "S"
const treeKeyPrefix4SubTreeValue string = "V"

type PasswerkApplication struct {
	// The state holds:
	//
	//   for each master username/password
	//      map record:  key - hashed master-username/master-password
	//                   values - list of encrypted cIdNames
	//   for each saved record
	//      main values: key - hashed master-usr/master-pwd/cIdName
	//                   values - encrypted cPassword
	//
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

	go httpListener(app)

	return app
}

func httpListener(app *PasswerkApplication) {
	http.HandleFunc("/", app.UIInputHandler)
	http.ListenAndServe(":"+portPasswerkUI, nil)
}

//returns the size of the tx
func (app *PasswerkApplication) Info() string {
	return Fmt("size:%v", app.state.Size())
}

//SetOption is currently unsupported
func (app *PasswerkApplication) SetOption(key, value string) (log string) {
	return ""
}

func badReturn(log string) types.Result {
	return types.Result{
		Code: types.CodeType_BadNonce,
		Data: nil,
		Log:  Fmt(log),
	}
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
		err := treeNewRecord(
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
		err := treeDeleteRecord(
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

		subTree, err := loadSubTree(&app.stateDB, app.state, usernameHashed, passwordHashed)
		if err != nil {
			return badReturn("bad sub tree")
		}

		treeRecordExists := subTree.Has(treeGetRecordKey(usernameHashed, passwordHashed, cIdNameHashed))
		_, mapValues, mapExists := subTree.Get(treeGetIdListKey(usernameHashed, passwordHashed))
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

//This method performs a broadcast_tx_commit call to tendermint
//<incomplete code> rather than returning the raw html, data should be parsed and return the code, data, and log
func broadcastTxFromString(tx string) string {
	urlStringBytes := []byte(tx)
	urlHexString := hex.EncodeToString(urlStringBytes[:])

	resp, err := http.Get(`http://localhost:` + portTendermint + `/broadcast_tx_commit?tx="` + urlHexString + `"`)
	htmlBytes, err := ioutil.ReadAll(resp.Body)
	htmlString := string(htmlBytes)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	return htmlString
}

//function handles http requests from the passwerk local host (not tendermint local host)
func (app *PasswerkApplication) UIInputHandler(w http.ResponseWriter, r *http.Request) {

	var err error

	UIoutput := "" //variable which holds the final output to be written by the program
	urlString := r.URL.Path[1:]
	speachBubble := "i h8 myslf"   //speach bubble text for the ASCII assailant
	notSelected := "<notSelected>" //text indicating that a piece of URL input has not been submitted

	var idNameList, //		list of all the stored records which will be output if requested by the user (readingIdNames)
		urlOptionText, //	1st URL section - <manditory>  indicates the user write mode
		urlUsername, //		2nd URL section - <manditory> master username to be read or written from
		urlPassword, //		3rd URL section - <manditory> master password to be read or written with
		urlCIdName, //		4th URL section - <optional> cipherable indicator name for the password
		urlCPassword string //	5th URL section - <optional> cipherable password to be stored

	//This function writes the user interface, used always before exiting the UIInputHandler
	writeUI := func() {
		UIoutput = getUIoutput(err, urlUsername, urlPassword, urlCIdName, speachBubble, idNameList)
		fmt.Fprintf(w, UIoutput)
	}

	//if there are less than three variables provided make a fuss
	if len(strings.Split(urlString, `/`)) < 3 {
		err = errors.New("not enough URL arguments")
		writeUI()
		return
	}

	var urlStringSplit [5]string
	temp := strings.Split(urlString, `/`)
	copy(urlStringSplit[:], temp)

	//initilize any elements that were not a part of the split
	for i, piece := range urlStringSplit {
		if len(piece) < 1 {
			urlStringSplit[i] = notSelected
		}
	}

	urlOptionText = urlStringSplit[0]
	urlUsername = urlStringSplit[1]
	urlPassword = urlStringSplit[2]
	urlCIdName = urlStringSplit[3]
	urlCPassword = urlStringSplit[4]

	//These two strings generated the hashes which are used for encryption and decryption of passwords
	//<sloppy code> is there maybe a more secure encryption method here?
	HashInputCIdNameEncryption := urlUsername + urlPassword
	HashInputCPasswordEncryption := urlCIdName + urlPassword + urlUsername

	var operationalOption string
	operationalOption, err = getOperationalOption(notSelected, urlOptionText, urlUsername,
		urlPassword, urlCIdName, urlCPassword)
	if err != nil {
		writeUI()
		return
	}

	//performing authentication (don't need to authenicate for writing passwords)
	if operationalOption != "writing" &&
		treeAuthenticate(app.state, getHashedHexString(urlUsername), getHashedHexString(urlPassword)) == false {
		err = errors.New("badAuthentication")
		writeUI()
		return
	}

	// performing operation
	switch operationalOption {
	case "readingIdNames":

		var idNameListArray []string
		idNameListArray, err = treeRetrieveCIdNames( //<sloppy code> add error handling
			&app.stateDB,
			app.state,
			getHashedHexString(urlUsername),
			getHashedHexString(urlPassword),
			HashInputCIdNameEncryption,
		)
		if err != nil {
			writeUI()
			return
		}

		speachBubble = "...psst down at my toes"

		for i := 0; i < len(idNameListArray); i++ {
			idNameList = idNameList + "\n" + idNameListArray[i]
		}

	case "readingPassword":
		var cPasswordDecrypted string
		cPasswordDecrypted, err = treeRetrieveCPassword(
			&app.stateDB,
			app.state,
			getHashedHexString(urlUsername),
			getHashedHexString(urlPassword),
			getHashedHexString(urlCIdName),
			HashInputCPasswordEncryption,
		)
		if err != nil {
			writeUI()
			return
		}
		speachBubble = cPasswordDecrypted

	case "deleting":
		//determine encrypted text to delete
		var mapCIdNameEncrypted2Delete string
		mapCIdNameEncrypted2Delete, err = treeGetCIdListEncryptedCIdName(
			&app.stateDB,
			app.state,
			getHashedHexString(urlUsername),
			getHashedHexString(urlPassword),
			urlCIdName,
			HashInputCIdNameEncryption,
		)

		if err != nil {
			writeUI()
			return
		}

		if len(mapCIdNameEncrypted2Delete) >= 0 {

			//create he tx then broadcast
			tx2broadcast := path.Join(
				timeStampString(),
				operationalOption,
				getHashedHexString(urlUsername),
				getHashedHexString(urlPassword),
				getHashedHexString(urlCIdName),
				mapCIdNameEncrypted2Delete)
			broadcastTxFromString(tx2broadcast)

			speachBubble = "*Chuckles* - nvr heard of no " + urlCIdName + " before"
		} else {
			err = errors.New("invalidCIdName")
			writeUI()
			return
		}

	case "writing":
		//before writing, any duplicate records must first be deleted
		//do not worry about error handling here for records that do not exist
		//  it doesn't really matter if there is nothing to delete
		var mapCIdNameEncrypted2Delete string
		mapCIdNameEncrypted2Delete, err = treeGetCIdListEncryptedCIdName(
			&app.stateDB,
			app.state,
			getHashedHexString(urlUsername),
			getHashedHexString(urlPassword),
			urlCIdName,
			HashInputCIdNameEncryption,
		)
		if len(mapCIdNameEncrypted2Delete) >= 0 && err == nil {

			//create he tx then broadcast
			tx2broadcast := path.Join(
				timeStampString(),
				"deleting",
				getHashedHexString(urlUsername),
				getHashedHexString(urlPassword),
				getHashedHexString(urlCIdName),
				mapCIdNameEncrypted2Delete)
			broadcastTxFromString(tx2broadcast)
		}

		//reset the error term because it doesn't matter if the record was non-existent
		err = nil

		//now write the records
		//create he tx then broadcast
		tx2broadcast := path.Join(
			timeStampString(),
			operationalOption,
			getHashedHexString(urlUsername),
			getHashedHexString(urlPassword),
			getHashedHexString(urlCIdName),
			getEncryptedHexString(HashInputCIdNameEncryption, urlCIdName),
			getEncryptedHexString(HashInputCPasswordEncryption, urlCPassword))
		broadcastTxFromString(tx2broadcast)

		speachBubble = "Roger That"
	}

	//Writing output
	writeUI()
	return
}

func getOperationalOption(notSelected, urlOptionText, urlUsername,
	urlPassword, urlCIdName, urlCPassword string) (string, error) {

	//This function returns true if any of the input array have the value of notSelected
	AnyAreNotSelected := func(inputs []string) bool {
		for i := 0; i < len(inputs); i++ {
			if inputs[i] == notSelected {
				return true
			}
		}
		return false
	}

	genErr := errors.New("generalError")

	switch urlOptionText {
	case "r":
		if AnyAreNotSelected([]string{urlUsername, urlPassword}) {
			return "", genErr
		} else if urlCIdName != notSelected {
			return "readingPassword", nil
		} else {
			return "readingIdNames", nil
		}

	case "w":
		if AnyAreNotSelected([]string{urlCIdName, urlCPassword, urlUsername, urlPassword}) {
			return "", genErr
		} else {
			return "writing", nil
		}
	case "d":
		if AnyAreNotSelected([]string{urlCIdName, urlUsername, urlPassword}) {
			return "", genErr
		} else {
			return "deleting", nil
		}
	default:
		return "", genErr
	}
}

func getUIoutput(err error, urlUsername, urlPassword, urlCIdName, speachBubble, idNameList string) string {

	// writing special speach bubbles for errors encounted
	if err != nil {
		switch err.Error() {
		case "generalError": //<sloppy code> add more types of specific error outputs
			speachBubble = "ugh... general error"

		case "badAuthentication":
			speachBubble = "do i know u?"

		case "invalidCIdName":
			speachBubble = "sry nvr heard of it </3"
		default:
			speachBubble = err.Error()
		}
	}

	return "passwerk" + `
 __________________________________________
|                                          |
|  u: ` + urlUsername + `
|  p: ` + urlPassword + `
|  id: ` + urlCIdName + `
|__________________________________________|	
	
	
*coughs*

      /||||\    {` + speachBubble + `}
     |-o-o-~|  / 
    _   ~       
   /        '\
  |    \ /   |    
  |     -    \__  _~
   \            '( )
    |)      |
 ___\___      \
/____/ |  | | |
| | || |  |_| |_
|   |  |____]___] 		

` + idNameList

}

func timeStampString() string {
	return time.Now().Format(time.StampMicro)
}

/////////////////////////////////////// tree operations

func treeGetMapKey(usernameHashed, passwordHashed string) []byte {
	return []byte(path.Join(treeKeyPrefix4SubTree, usernameHashed, passwordHashed))
}

func treeGetIdListKey(usernameHashed, passwordHashed string) []byte {
	return []byte(path.Join(treeKeyPrefix4SubTreeValue, usernameHashed, passwordHashed))
}
func treeGetRecordKey(usernameHashed, passwordHashed, cIdNameHashed string) []byte {
	return []byte(path.Join(treeKeyPrefix4SubTreeValue, usernameHashed, passwordHashed, cIdNameHashed))
}

func treeAuthenticate(state merkle.Tree, usernameHashed, passwordHashed string) bool {
	mapKey := treeGetMapKey(usernameHashed, passwordHashed)
	return state.Has(mapKey)
}

//the momma merkle tree has sub-merkle tree state (output for .Save())
// stored as the value in the key-value pair in the momma tree
func loadSubTree(dbIn *db.DB, mommaTree merkle.Tree, usernameHashed, passwordHashed string) (merkle.Tree, error) {

	subTree := merkle.NewIAVLTree(merkleCacheSize, *dbIn)
	_, treeOutHash2Load, exists := mommaTree.Get(treeGetMapKey(usernameHashed, passwordHashed))
	if exists == false {
		return nil, errors.New("sub tree doesn't exist")
	}

	subTree.Load(treeOutHash2Load)

	return subTree, nil
}

func saveSubTree(subTree, mommaTree merkle.Tree, usernameHashed, passwordHashed string) {
	mommaTree.Set(treeGetMapKey(usernameHashed, passwordHashed), subTree.Save())
}

func newSubTree(dbIn *db.DB, mommaTree merkle.Tree, usernameHashed, passwordHashed string) merkle.Tree {
	subTree := merkle.NewIAVLTree(merkleCacheSize, *dbIn)
	mommaTree.Set(treeGetMapKey(usernameHashed, passwordHashed), subTree.Save())
	return subTree
}

func treeRetrieveCIdNames(dbIn *db.DB, state merkle.Tree, usernameHashed, passwordHashed,
	hashInputCIdNameEncryption string) (cIdNamesEncrypted []string, err error) {

	subTree, err := loadSubTree(dbIn, state, usernameHashed, passwordHashed)

	cIdListKey := treeGetIdListKey(usernameHashed, passwordHashed)
	if subTree.Has(cIdListKey) {
		_, mapValues, _ := subTree.Get(cIdListKey)

		//get the encrypted cIdNames
		cIdNames := strings.Split(string(mapValues), "/")

		//decrypt the cIdNames
		for i := 0; i < len(cIdNames); i++ {
			if len(cIdNames[i]) < 1 {
				continue
			}
			cIdNames[i], err = readDecrypted(hashInputCIdNameEncryption, cIdNames[i])
		}
		return cIdNames, err
	} else {
		err = errors.New("badAuthentication")
		return nil, err
	}
}

func treeRetrieveCPassword(dbIn *db.DB, state merkle.Tree, usernameHashed, passwordHashed, cIdNameHashed,
	hashInputCPasswordEncryption string) (cPassword string, err error) {

	subTree, err := loadSubTree(dbIn, state, usernameHashed, passwordHashed)

	cPasswordKey := treeGetRecordKey(usernameHashed, passwordHashed, cIdNameHashed)
	_, cPasswordEncrypted, exists := subTree.Get(cPasswordKey)
	if exists {
		cPassword, err = readDecrypted(hashInputCPasswordEncryption, string(cPasswordEncrypted))
		return
	} else {
		err = errors.New("invalidCIdName")
		return
	}
}

func treeDeleteRecord(dbIn *db.DB, state merkle.Tree, usernameHashed, passwordHashed, cIdNameHashed,
	cIdNameEncrypted string) (err error) {

	var subTree merkle.Tree

	subTree, err = loadSubTree(dbIn, state, usernameHashed, passwordHashed)

	//verify the record exists
	merkleRecordKey := treeGetRecordKey(usernameHashed, passwordHashed, cIdNameHashed)
	cIdListKey := treeGetIdListKey(usernameHashed, passwordHashed)
	_, cIdListValues, cIdListExists := subTree.Get(cIdListKey)

	if subTree.Has(merkleRecordKey) == false ||
		cIdListExists == false {
		err = errors.New("record to delete doesn't exist")
		return
	}

	//delete the main record from the merkle tree
	_, successfulRemove := subTree.Remove(merkleRecordKey)
	if successfulRemove == false {
		err = errors.New("error deleting the record from subTree")
		return
	}

	//delete the index from the cIdName list
	oldCIdListValues := string(cIdListValues)
	newCIdListValues := strings.Replace(oldCIdListValues, "/"+cIdNameEncrypted+"/", "/", 1)
	subTree.Set(cIdListKey, []byte(newCIdListValues))

	fmt.Println(newCIdListValues)

	//save the subTree
	saveSubTree(subTree, state, usernameHashed, passwordHashed)

	//If there are no more values within the CIdList, then delete the CIdList
	//   as well as the main username password sub tree
	_, cIdListValues, _ = subTree.Get(cIdListKey)
	if len(string(cIdListValues)) < 2 {
		subTree.Remove(cIdListKey)
		state.Remove(treeGetMapKey(usernameHashed, passwordHashed))
	}

	return
}

func treeGetCIdListEncryptedCIdName(dbIn *db.DB, state merkle.Tree, usernameHashed, passwordHashed, cIdNameUnencrypted,
	hashInputCIdNameEncryption string) (cIdNameOrigEncrypted string, err error) {

	var subTree merkle.Tree
	subTree, err = loadSubTree(dbIn, state, usernameHashed, passwordHashed)
	if err != nil {
		return
	}

	cIdListKey := treeGetIdListKey(usernameHashed, passwordHashed)
	_, cIdListValues, exists := subTree.Get(cIdListKey)

	if exists == false {
		err = errors.New("sub tree doesn't exist")
		return
	}

	//get the encrypted cIdNames
	cIdNames := strings.Split(string(cIdListValues), "/")

	//determine the correct value from the cIdNames array and return
	for i := 0; i < len(cIdNames); i++ {
		if len(cIdNames[i]) < 1 {
			continue
		}
		var tempCIdNameDecrypted string
		tempCIdNameDecrypted, err = readDecrypted(hashInputCIdNameEncryption, cIdNames[i])

		//remove record from master list and merkle tree
		if cIdNameUnencrypted == tempCIdNameDecrypted {
			cIdNameOrigEncrypted = cIdNames[i]
		}
	}

	return
}

//must delete any records with the same cIdName before adding a new record
func treeNewRecord(dbIn *db.DB, state merkle.Tree, usernameHashed, passwordHashed, cIdNameHashed,
	cIdNameEncrypted, cPasswordEncrypted string) (err error) {

	var subTree merkle.Tree

	mapKey := treeGetMapKey(usernameHashed, passwordHashed)
	cIdListKey := treeGetIdListKey(usernameHashed, passwordHashed)

	//if the relavant subTree does not exist
	//  create the subtree as well as the cIdList
	if state.Has(mapKey) {
		subTree, err = loadSubTree(dbIn, state, usernameHashed, passwordHashed)
		if err != nil {
			fmt.Println(err)
			return
		}
		_, cIdListValues, _ := subTree.Get(cIdListKey)
		subTree.Set(cIdListKey, []byte(string(cIdListValues)+cIdNameEncrypted+"/"))

	} else {
		subTree = newSubTree(dbIn, state, usernameHashed, passwordHashed)
		subTree.Set(cIdListKey, []byte("/"+cIdNameEncrypted+"/"))
	}

	//create the new record in the tree
	insertKey := treeGetRecordKey(usernameHashed, passwordHashed, cIdNameHashed)
	insertValues := []byte(cPasswordEncrypted)
	subTree.Set(insertKey, insertValues)

	saveSubTree(subTree, state, usernameHashed, passwordHashed)

	fmt.Println("state num records: " + strconv.Itoa(state.Size()))
	fmt.Println("subTree num records: " + strconv.Itoa(subTree.Size()))

	return
}

////////////////////////////////////////////////////////////// tree logic end

//read and decrypt from the hashPasswordList
func readDecrypted(hashInput, encryptedString string) (decryptedString string, err error) {

	var key [32]byte
	copy(key[:], getHash(hashInput))

	var ciphertext, decryptedByte []byte

	ciphertext, err = hex.DecodeString(encryptedString)
	decryptedByte, err = decryptNaCl(&key, ciphertext)
	decryptedString = string(decryptedByte[:])

	return
}

//return an encrypted string. the encyption key is taken as hashed value of the input variable hashInput
func getEncryptedHexString(hashInput, unencryptedString string) string {

	var key [32]byte
	copy(key[:], getHash(hashInput))

	encryptedByte, err := encryptNaCl(&key, []byte(unencryptedString))

	if err == nil {
		encryptedHexString := hex.EncodeToString(encryptedByte[:])
		return encryptedHexString
	}

	return ""
}

func bytes2HexString(dataInput []byte) string {
	return hex.EncodeToString(dataInput[:])
}

//return datainput as a hex string after it has been hashed
func getHashedHexString(dataInput string) string {

	//performing the hash
	hashBytes := getHash(dataInput)

	//encoding to a hex string, within data the [x]byte array sliced to []byte (shorthand for h[0:len(h)])
	hashHexString := bytes2HexString(hashBytes)
	return hashHexString
}

func getHash(dataInput string) []byte {
	//performing the hash
	hashBytes := sha3.Sum256([]byte(dataInput))
	return hashBytes[:]
}

func encryptNaCl(key *[32]byte, text []byte) (ciphertext []byte, err error) {

	var nonce [24]byte

	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return
	}

	//crypted := make([]byte, 0, box.Overhead+len(message))

	ciphertext = box.SealAfterPrecomputation([]byte(""), text, &nonce, key)
	ciphertext = append(nonce[:], ciphertext...)

	return
}

func decryptNaCl(key *[32]byte, ciphertext []byte) (plaintext []byte, err error) {

	var nonce [24]byte
	copy(nonce[:], ciphertext[:24])

	cipherMessage := ciphertext[24:]

	plaintext, success := box.OpenAfterPrecomputation([]byte(""), cipherMessage, &nonce, key)

	if success == false {
		err = errors.New("bad decryption")
		return
	}

	return
}