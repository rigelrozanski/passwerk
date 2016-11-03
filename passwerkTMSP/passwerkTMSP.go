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
// 	master_username - The master username that is non-retrievable
//      master_password - The master password that is non-retrievable
//      identifier - a retrievable unique identifier for a saved password
//      savedpassword - a retrievable saved password associated with an identifier
//
// EXAMPLES:
//
// writing a new record to the system:
//	http://localhost:8080/w/master_username/master_password/idenfier/savedpassword
//
// reading list of identifiers of all the saved passwords for a given master-username/master-password
//	http://localhost:8080/w/master_username/master_password/idenfier/savedpassword
//
// reading a saved password for a given master-username/master-password/identifier
//	http://localhost:8080/w/master_username/master_password/idenfier/savedpassword
//
// deleting a saved password/identifier for a given master-username/master-password/identifier
//	http://localhost:8080/w/master_username/master_password/idenfier/savedpassword
//

package passwerkTMSP

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/sha3"
	"io"
	"io/ioutil"
	"net/http"
	"path"
	//"strconv"
	"strings"
	"time"

	. "github.com/tendermint/go-common"
	"github.com/tendermint/go-merkle"
	"github.com/tendermint/tmsp/types"
)

const portPasswerkUI string = "8080"
const portTendermint string = "46657"

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
	state merkle.Tree
}

func NewPasswerkApplication() *PasswerkApplication {

	state := merkle.NewIAVLTree(0, nil)
	app := &PasswerkApplication{state: state}
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
		treeNewRecord(
			app.state,
			parts[2], //usernameHashed
			parts[3], //passwordashed
			parts[4], //cIdNameHashed
			parts[5], //cIdNameEncrypted
			parts[6]) //cPasswordEncrypted
	case "deleting":
		treeDeleteRecord(
			app.state,
			parts[2], //usernameHashed
			parts[3], //passwordHashed
			parts[4], //cIdNameHashed
			parts[5]) //cIdNameEncrypted
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
//     from multiple users on the same system.
func (app *PasswerkApplication) CheckTx(tx []byte) types.Result {

	//seperate the tx into all the parts to be written
	parts := strings.Split(string(tx), "/")

	badReturn := func(log string) types.Result {
		return types.Result{
			Code: types.CodeType_BadNonce,
			Data: nil,
			Log:  Fmt(log),
		}
	}

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

		//For Reference below
		//parts[2], //usernameHashed
		//parts[3], //passwordHashed
		//parts[4], //cIdNameHashed
		//parts[5]) //cIdNameEncrypted

		treeRecordExists := app.state.Has(treeGetRecordKey(parts[2], parts[3], parts[4]))
		_, mapValues, mapExists := app.state.Get(treeGetMapKey(parts[2], parts[3]))
		containsCIdNameEncrypted := strings.Contains(string(mapValues), "/"+parts[5]+"/")

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
	htmlBytes, _ := ioutil.ReadAll(resp.Body)
	htmlString := string(htmlBytes)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	return htmlString
}

//function handles http requests from the passwerk local host (not tendermint local host)
func (app *PasswerkApplication) UIInputHandler(w http.ResponseWriter, r *http.Request) {

	UIoutput := "" //variable which holds the final output to be written by the program
	urlString := r.URL.Path[1:]
	speachBubble := "i h8 myslf"   //speach bubble text for the ASCII assailant
	notSelected := "<notSelected>" //text indicating that a piece of URL input has not been submitted

	//if there are less than three variables provided make a fuss
	if len(strings.Split(urlString, `/`)) < 3 {
		UIoutput = getUIoutput("", "", "", speachBubble, "") //<sloppy code> should provide some indicator to the user as to what the problem is
		fmt.Fprintf(w, UIoutput)
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

	idNameList := ""                   //list of all the stored records which will be output if requested by the user (reading_IdNames)
	urlOptionText := urlStringSplit[0] //1st URL section - <manditory>  indicates the user write mode
	urlUsername := urlStringSplit[1]   //2nd URL section - <manditory> master username to be read or written from
	urlPassword := urlStringSplit[2]   //3rd URL section - <manditory> master password to be read or written with
	urlCIdName := urlStringSplit[3]    //4th URL section - <optional> cipherable indicator name for the password
	urlCPassword := urlStringSplit[4]  //5th URL section - <optional> cipherable password to be stored

	// reading inputs from URL
	// needs to be in a for loop to check for variable length input to urlStringSplit
	// to avoid array index out of bounds
	//	for i := 0; i < len(urlStringSplit); i++ {
	//		switch i {
	//		case 0:
	//			urlOptionText = urlStringSplit[i]
	//		case 1:
	//			urlUsername = urlStringSplit[i]
	//		case 2:
	//			urlPassword = urlStringSplit[i]
	//		case 3:
	//			urlCIdName = urlStringSplit[i]
	//		case 4:
	//			urlCPassword = urlStringSplit[i]
	//		}
	//	}

	//These two strings generated the hashes which are used for encryption and decryption of passwords
	//<sloppy code> is there maybe a more secure encryption method here?
	HashInputCIdNameEncryption := urlUsername + urlPassword
	HashInputCPasswordEncryption := urlCIdName + urlPassword + urlUsername

	operationalOption := getOperationalOption(notSelected, urlOptionText, urlUsername,
		urlPassword, urlCIdName, urlCPassword)

	//performing authentication (don't need to authenicate for writing passwords)
	if operationalOption != "writing" &&
		treeAuthenticate(app.state, getHashedHexString(urlUsername), getHashedHexString(urlPassword)) == false {
		operationalOption = "ERRORAuthentication"
	}

	// performing operation
	switch operationalOption {
	case "readingIdNames": //  <sloppy code> consider moving this section to query

		idNameListArray := treeRetrieveCIdNames(
			app.state,
			getHashedHexString(urlUsername),
			getHashedHexString(urlPassword),
			HashInputCIdNameEncryption)
		speachBubble = "...psst down at my toes"

		for i := 0; i < len(idNameListArray); i++ {
			idNameList = idNameList + "\n" + idNameListArray[i]
		}

	case "readingPassword": // <sloppy code> consider moving this section to query

		cPasswordDecrypted := treeRetrieveCPassword(
			app.state,
			getHashedHexString(urlUsername),
			getHashedHexString(urlPassword),
			getHashedHexString(urlCIdName),
			HashInputCPasswordEncryption)

		if cPasswordDecrypted != "" {
			speachBubble = cPasswordDecrypted
		} else {
			operationalOption = "ERRORInvalidIdName"
		}

	case "deleting":
		//determine the operation index
		mapCIdNameEncrypted2Delete := treeGetMapEncryptedCIdName(
			app.state,
			getHashedHexString(urlUsername),
			getHashedHexString(urlPassword),
			urlCIdName,
			HashInputCIdNameEncryption)
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
			operationalOption = "ERRORInvalidIdName"
		}

	case "writing":
		//before writing, any duplicate records must first be deleted
		//determine the operation index
		mapCIdNameEncrypted2Delete := treeGetMapEncryptedCIdName(
			app.state,
			getHashedHexString(urlUsername),
			getHashedHexString(urlPassword),
			urlCIdName,
			HashInputCIdNameEncryption)
		if len(mapCIdNameEncrypted2Delete) >= 0 {

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

	// writing speach bubbles for any errors encounted
	switch operationalOption {
	case "ERRORGeneral": //<sloppy code> add more types of specific error outputs
		speachBubble = "ugh... general error"

	case "ERRORAuthentication":
		speachBubble = "do i know u?"

	case "ERRORInvalidIdName":
		speachBubble = "sry nvr heard of it </3"
	}

	//Writing output
	UIoutput = getUIoutput(urlUsername, urlPassword, urlCIdName, speachBubble, idNameList)
	fmt.Fprintf(w, UIoutput)
}

func getOperationalOption(notSelected, urlOptionText, urlUsername,
	urlPassword, urlCIdName, urlCPassword string) string {

	//OR equiv. - false if any are not selected
	AnyAreNotSelected := func(inputs []string) bool {
		for i := 0; i < len(inputs); i++ {
			if inputs[i] == notSelected {
				return true
			}
		}
		return false
	}

	genERROR := "ERRORGeneral"

	switch urlOptionText {
	case "r":
		if AnyAreNotSelected([]string{urlUsername, urlPassword}) {
			return genERROR
		} else if urlCIdName != notSelected {
			return "readingPassword"
		} else {
			return "readingIdNames"
		}

	case "w":
		if AnyAreNotSelected([]string{urlCIdName, urlCPassword, urlUsername, urlPassword}) {
			return genERROR
		} else {
			return "writing"
		}
	case "d":
		if AnyAreNotSelected([]string{urlCIdName, urlUsername, urlPassword}) {
			return genERROR
		} else {
			return "deleting"
		}
	default:
		return genERROR
	}
}

func getUIoutput(urlUsername, urlPassword, urlCIdName, speachBubble, idNameList string) string {
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

func treeGetMapKey(usernameHashed, passwordHashed string) []byte {
	return []byte(path.Join(usernameHashed, passwordHashed))
}

func treeGetRecordKey(usernameHashed, passwordHashed, cIdNameHashed string) []byte {
	return []byte(path.Join(usernameHashed, passwordHashed, cIdNameHashed))
}

func treeAuthenticate(state merkle.Tree, usernameHashed, passwordHashed string) bool {
	mapKey := treeGetMapKey(usernameHashed, passwordHashed)
	return state.Has(mapKey)
}

func treeRetrieveCIdNames(state merkle.Tree, usernameHashed, passwordHashed,
	hashInputCIdNameEncryption string) (cIdNamesEncrypted []string) {

	mapKey := treeGetMapKey(usernameHashed, passwordHashed)
	_, mapValues, exists := state.Get(mapKey)
	if exists {

		//get the encrypted cIdNames
		cIdNames := strings.Split(string(mapValues), "/")

		//decrypt the cIdNames
		for i := 0; i < len(cIdNames); i++ {
			if len(cIdNames[i]) < 1 {
				continue
			}
			cIdNames[i], _ = readDecrypted(hashInputCIdNameEncryption, cIdNames[i])
		}
		return cIdNames
	} else {
		return nil
	}
}

func treeRetrieveCPassword(state merkle.Tree, usernameHashed, passwordHashed, cIdNameHashed,
	hashInputCPasswordEncryption string) string {

	cPasswordKey := treeGetRecordKey(usernameHashed, passwordHashed, cIdNameHashed)
	_, cPasswordEncrypted, exists := state.Get(cPasswordKey)
	if exists {
		cPassword, _ := readDecrypted(hashInputCPasswordEncryption, string(cPasswordEncrypted))
		return cPassword
	} else {
		return ""
	}
}

func treeDeleteRecord(state merkle.Tree, usernameHashed, passwordHashed, cIdNameHashed,
	cIdNameEncrypted string) (success bool) {

	//verify the record exists
	merkleRecordKey := treeGetRecordKey(usernameHashed, passwordHashed, cIdNameHashed)
	mapKey := treeGetMapKey(usernameHashed, passwordHashed)
	_, mapValues, mapExists := state.Get(mapKey)

	if state.Has(merkleRecordKey) == false ||
		mapExists == false {
		return false
	}

	//delete the main record from the merkle tree
	_, successfulRemove := state.Remove(merkleRecordKey)
	if successfulRemove == false {
		return false
	}

	//delete the index from the map
	oldMapValues := string(mapValues)
	newMapValues := strings.Replace(oldMapValues, "/"+cIdNameEncrypted+"/", "/", 1)
	state.Set(mapKey, []byte(newMapValues))

	//delete the map too if there are no more values within it!
	_, mapValues, _ = state.Get(mapKey)
	if len(string(mapValues)) < 2 {
		state.Remove(mapKey)
	}

	return true
}

func treeGetMapEncryptedCIdName(state merkle.Tree, usernameHashed, passwordHashed, cIdNameUnencrypted,
	hashInputCIdNameEncryption string) string {

	cIdNameOrigEncrypted := ""

	mapKey := treeGetMapKey(usernameHashed, passwordHashed)
	_, mapValues, exists := state.Get(mapKey)
	if exists == false {
		return cIdNameOrigEncrypted
	}

	//get the encrypted cIdNames
	cIdNames := strings.Split(string(mapValues), "/")

	//determine the correct value from the cIdNames array and return
	for i := 0; i < len(cIdNames); i++ {
		if len(cIdNames[i]) < 1 {
			continue
		}
		tempCIdNameDecrypted, _ := readDecrypted(hashInputCIdNameEncryption, cIdNames[i])

		//remove record from master list and merkle tree
		if cIdNameUnencrypted == tempCIdNameDecrypted {
			cIdNameOrigEncrypted = cIdNames[i]
		}
	}

	return cIdNameOrigEncrypted
}

//must delete any records with the same cIdName before adding a new record
func treeNewRecord(state merkle.Tree, usernameHashed, passwordHashed, cIdNameHashed,
	cIdNameEncrypted, cPasswordEncrypted string) {

	mapKey := treeGetMapKey(usernameHashed, passwordHashed)

	//get the newIndex and add it to the master list/create the master list if doesn't exist
	if state.Has(mapKey) {
		_, mapValues, _ := state.Get(mapKey)
		state.Set(mapKey, []byte(string(mapValues)+cIdNameEncrypted+"/"))
	} else {
		state.Set(mapKey, []byte("/"+cIdNameEncrypted+"/"))
	}

	//create the new record in the tree
	insertKey := treeGetRecordKey(usernameHashed, passwordHashed, cIdNameHashed)
	insertValues := []byte(cPasswordEncrypted)
	state.Set(insertKey, insertValues)
}

//read and decrypt from the hashPasswordList
func readDecrypted(hashInput, encryptedString string) (decryptedString string, err error) {

	// The key length must be 32, 24, or 16  bytes
	key := getHash(hashInput)
	var ciphertext, decryptedByte []byte

	ciphertext, err = hex.DecodeString(encryptedString)
	decryptedByte, err = decrypt(key, ciphertext)
	decryptedString = string(decryptedByte[:])

	return
}

//return an encrypted string. the encyption key is taken as hashed value of the input variable hashInput
func getEncryptedHexString(hashInput, unencryptedString string) string {

	// The key length must be 32, 24, or 16  bytes
	key := getHash(hashInput)
	encryptedByte, err := encrypt(key, []byte(unencryptedString))

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

func encrypt(key, text []byte) (ciphertext []byte, err error) {

	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return nil, err
	}

	ciphertext = make([]byte, aes.BlockSize+len(string(text)))

	// iv =  initialization vector
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)

	return
}

func decrypt(key, ciphertext []byte) (plaintext []byte, err error) {

	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	if len(ciphertext) < aes.BlockSize {
		err = errors.New("ciphertext too short")
		return
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(ciphertext, ciphertext)

	plaintext = ciphertext

	return
}
