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

package passwerk_TMSP

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
	"strconv"
	"strings"
	"time"

	. "github.com/tendermint/go-common"
	"github.com/tendermint/go-merkle"
	"github.com/tendermint/tmsp/types"
)

const port_passwerkUI string = "8080"
const port_tendermint string = "46657"

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
	http.HandleFunc("/", app.UI_inputHandler)
	http.ListenAndServe(":"+port_passwerkUI, nil)
}

//returns the size of the tx
func (app *PasswerkApplication) Info() string {
	return Fmt("size:%v", app.state.Size())
}

//SetOption is currently unsupported
func (app *PasswerkApplication) SetOption(key string, value string) (log string) {
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
		tree_NewRecord(
			app.state,
			parts[2], //username_Hashed
			parts[3], //password_Hashed
			parts[4], //cIdName_Hashed
			parts[5], //cIdName_Encrypted
			parts[6]) //cPassword_Encrypted
	case "deleting":
		mapIndex2Delete, _ := strconv.Atoi(parts[5])
		tree_DeleteRecord(
			app.state,
			parts[2],        //username_Hashed
			parts[3],        //password_Hashed
			parts[4],        //cIdName_Hashed
			mapIndex2Delete) //mapIndex2Delete
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
		if len(parts) < 7 { //note that the length for deleting and writing just happens to be the same, may change in future passwerk
			return badReturn("Invalid number of TX parts")
		}

		//check to make sure that system state hasn't changed
		if parts[3] != bytes2HexString(app.state.Hash()) { //here parts[3] has passed on the system state from the broadcast
			return badReturn("System state has changed")
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
func broadcastTx_fromString(tx string) string {
	urlStringBytes := []byte(tx)
	urlHexString := hex.EncodeToString(urlStringBytes[:])

	resp, err := http.Get(`http://localhost:` + port_tendermint + `/broadcast_tx_commit?tx="` + urlHexString + `"`)
	htmlBytes, _ := ioutil.ReadAll(resp.Body)
	htmlString := string(htmlBytes)
	if err != nil {
		panic(err)
	}
	resp.Body.Close()

	return htmlString
}

//function handles http requests from the passwerk local host (not tendermint local host)
func (app *PasswerkApplication) UI_inputHandler(w http.ResponseWriter, r *http.Request) {

	UIoutput := "" //variable which holds the final output to be written by the program
	urlString := r.URL.Path[1:]
	urlStringSplit := strings.Split(urlString, `/`)

	speachBubble := "i h8 myslf" //speach bubble text for the ASCII assailant

	if len(urlStringSplit) < 3 {
		UIoutput = getUIoutput("", "", "", speachBubble, "") //<sloppy code> should provide some indicator to the user as to what the problem is
		fmt.Fprintf(w, UIoutput)
		return
	}

	notSelected := "<notSelected>" //text indicating that a piece of URL input has not been submitted
	idNameList := ""               //list of all the stored records which will be output if requested by the user (reading_IdNames)
	URL_optionText := notSelected  //1st URL section - <manditory>  indicates the user write mode
	URL_username := notSelected    //2nd URL section - <manditory> master username to be read or written from
	URL_password := notSelected    //3rd URL section - <manditory> master password to be read or written with
	URL_cIdName := notSelected     //4th URL section - <optional> cipherable indicator name for the password
	URL_cPassword := notSelected   //5th URL section - <optional> cipherable password to be stored

	// reading inputs from URL
	// needs to be in a for loop to check for variable length input to urlStringSplit
	// to avoid array index out of bounds
	for i := 0; i < len(urlStringSplit); i++ {
		switch i {
		case 0:
			URL_optionText = urlStringSplit[i]
		case 1:
			URL_username = urlStringSplit[i]
		case 2:
			URL_password = urlStringSplit[i]
		case 3:
			URL_cIdName = urlStringSplit[i]
		case 4:
			URL_cPassword = urlStringSplit[i]
		}
	}

	//These two strings generated the hashes which are used for encryption and decryption of passwords
	//<sloppy code> is there maybe a more secure encryption method here?
	HashInput_cIdNameEncryption := URL_username + URL_password
	HashInput_cPasswordEncryption := URL_cIdName + URL_password + URL_username

	operationalOption := getOperationalOption(notSelected, URL_optionText, URL_username,
		URL_password, URL_cIdName, URL_cPassword)

	//performing authentication (don't need to authenicate for writing passwords)
	if operationalOption != "writing" &&
		tree_Authenticate(app.state, getHashedHexString(URL_username), getHashedHexString(URL_password)) == false {
		operationalOption = "ERROR_Authentication"
	}

	// performing operation
	switch operationalOption {
	case "reading_IdNames": //  <sloppy code> consider moving this section to query

		idNameListArray := tree_Retrieve_cIdNames(
			app.state,
			getHashedHexString(URL_username),
			getHashedHexString(URL_password),
			HashInput_cIdNameEncryption)
		speachBubble = "...psst down at my toes"

		for i := 0; i < len(idNameListArray); i++ {
			idNameList = idNameList + "\n" + idNameListArray[i]
		}

	case "reading_Password": // <sloppy code> consider moving this section to query

		cPassword_decrypted := tree_Retrieve_cPassword(
			app.state,
			getHashedHexString(URL_username),
			getHashedHexString(URL_password),
			getHashedHexString(URL_cIdName),
			HashInput_cPasswordEncryption)

		if cPassword_decrypted != "" {
			speachBubble = cPassword_decrypted
		} else {
			operationalOption = "ERROR_InvalidIdName"
		}

	case "deleting":
		//determine the operation index
		mapIndex, mapHash := tree_GetMapValueIndex(
			app.state,
			getHashedHexString(URL_username),
			getHashedHexString(URL_password),
			URL_cIdName,
			HashInput_cIdNameEncryption)
		if mapIndex >= 0 {

			//create he tx then broadcast
			tx2broadcast := path.Join(
				timeStampString(),
				operationalOption,
				getHashedHexString(URL_username),
				getHashedHexString(URL_password),
				getHashedHexString(URL_cIdName),
				strconv.Itoa(mapIndex),
				mapHash)
			broadcastTx_fromString(tx2broadcast)

			speachBubble = "*Chuckles* - nvr heard of no " + URL_cIdName + " before"
		} else {
			operationalOption = "ERROR_InvalidIdName"
		}

	case "writing":
		//before writing, any duplicate records must first be deleted
		//determine the operation index
		mapIndex, mapHash := tree_GetMapValueIndex(
			app.state,
			getHashedHexString(URL_username),
			getHashedHexString(URL_password),
			URL_cIdName,
			HashInput_cIdNameEncryption)
		if mapIndex >= 0 {

			//create he tx then broadcast
			tx2broadcast := path.Join(
				timeStampString(),
				"deleting",
				getHashedHexString(URL_username),
				getHashedHexString(URL_password),
				getHashedHexString(URL_cIdName),
				strconv.Itoa(mapIndex),
				mapHash)
			broadcastTx_fromString(tx2broadcast)
		}

		//now write the records
		//create he tx then broadcast
		tx2broadcast := path.Join(
			timeStampString(),
			operationalOption,
			getHashedHexString(URL_username),
			getHashedHexString(URL_password),
			getHashedHexString(URL_cIdName),
			getEncryptedHexString(HashInput_cIdNameEncryption, URL_cIdName),
			getEncryptedHexString(HashInput_cPasswordEncryption, URL_cPassword))
		broadcastTx_fromString(tx2broadcast)

		speachBubble = "Roger That"
	}

	// writing speach bubbles for any errors encounted
	switch operationalOption {
	case "ERROR_General": //<sloppy code> add more types of specific error outputs
		speachBubble = "ugh... general error"

	case "ERROR_Authentication":
		speachBubble = "do i know u?"

	case "ERROR_InvalidIdName":
		speachBubble = "sry nvr heard of it </3"
	}

	//Writing output
	UIoutput = getUIoutput(URL_username, URL_password, URL_cIdName, speachBubble, idNameList)
	fmt.Fprintf(w, UIoutput)
}

func getOperationalOption(notSelected string, URL_optionText string, URL_username string,
	URL_password string, URL_cIdName string, URL_cPassword string) string {

	//OR equiv. - false if any are not selected
	AnyAreNotSelected := func(inputs []string) bool {
		for i := 0; i < len(inputs); i++ {
			if inputs[i] == notSelected {
				return true
			}
		}
		return false
	}

	gen_ERROR := "ERROR_General"

	switch URL_optionText {
	case "r":
		if AnyAreNotSelected([]string{URL_username, URL_password}) {
			return gen_ERROR
		} else if URL_cIdName != notSelected {
			return "reading_Password"
		} else {
			return "reading_IdNames"
		}

	case "w":
		if AnyAreNotSelected([]string{URL_cIdName, URL_cPassword, URL_username, URL_password}) {
			return gen_ERROR
		} else {
			return "writing"
		}
	case "d":
		if AnyAreNotSelected([]string{URL_cIdName, URL_username, URL_password}) {
			return gen_ERROR
		} else {
			return "deleting"
		}
	default:
		return gen_ERROR
	}
}

func getUIoutput(URL_username string, URL_password string, URL_cIdName string,
	speachBubble string, idNameList string) string {
	return "passwerk" + `
 __________________________________________
|                                          |
|  u: ` + URL_username + `
|  p: ` + URL_password + `
|  id: ` + URL_cIdName + `
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

func tree_Authenticate(state merkle.Tree, username_Hashed string, password_Hashed string) bool {
	mapKey := []byte(path.Join(username_Hashed, password_Hashed))
	return state.Has(mapKey)
}

func tree_Retrieve_cIdNames(state merkle.Tree, username_Hashed string, password_Hashed string,
	hashInput_cIdNameEncryption string) (cIdNames_Encrypted []string) {

	mapKey := []byte(path.Join(username_Hashed, password_Hashed))
	_, mapValues, exists := state.Get(mapKey)
	if exists {

		//get the encrypted cIdNames
		cIdNames := strings.Split(string(mapValues), "/")

		//decrypt the cIdNames
		for i := 0; i < len(cIdNames); i++ {
			if len(cIdNames[i]) < 1 {
				continue
			}
			cIdNames[i], _ = readDecrypted(hashInput_cIdNameEncryption, cIdNames[i])
		}
		return cIdNames
	} else {
		return nil
	}
}

func tree_Retrieve_cPassword(state merkle.Tree, username_Hashed string, password_Hashed string, cIdName_Hashed string,
	hashInput_cPasswordEncryption string) string {

	cPasswordKey := []byte(path.Join(username_Hashed, password_Hashed, cIdName_Hashed))
	_, cPassword_Encrypted, exists := state.Get(cPasswordKey)
	if exists {
		cPassword, _ := readDecrypted(hashInput_cPasswordEncryption, string(cPassword_Encrypted))
		return cPassword
	} else {
		return ""
	}
}

func tree_DeleteRecord(state merkle.Tree, username_Hashed string, password_Hashed string, cIdName_Hashed string,
	map_Index2Remove int) (success bool) {

	//verify the record exists
	merkleRecordKey := []byte(path.Join(username_Hashed, password_Hashed, cIdName_Hashed))
	mapKey := []byte(path.Join(username_Hashed, password_Hashed))
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
	oldMapValuesSplit := strings.Split(string(mapValues), "/")
	mapValuesNew := "/" //the map always starts and ends with a backslash always

	//recomplile the masterValues to masterValuesNew, skipping the removed index
	for i := 0; i < len(oldMapValuesSplit); i++ {
		if len(oldMapValuesSplit[i]) < 1 || i == map_Index2Remove { //<sloppy code> this prevents users from saving a password of length zero, should account for this
			continue
		}
		mapValuesNew += oldMapValuesSplit[i] + "/"
		//remove record from master list and merkle tree
	}

	//delete the map too if there are no more values within it!
	_, mapValues, _ = state.Get(mapKey)
	if len(string(mapValues)) < 2 {
		state.Remove(mapKey)
	}

	return true
}

func tree_GetMapValueIndex(state merkle.Tree, username_Hashed string, password_Hashed string, cIdName_Unencrypted string,
	hashInput_cIdNameEncryption string) (mapIndex int, mapHash string) {

	outIndex := -1

	mapKey := []byte(path.Join(username_Hashed, password_Hashed))
	_, mapValues, exists := state.Get(mapKey)
	if exists == false {
		return outIndex, bytes2HexString(state.Hash())
	}

	//get the encrypted cIdNames
	cIdNames := strings.Split(string(mapValues), "/")

	//determine the correct index
	for i := 0; i < len(cIdNames); i++ {
		if len(cIdNames[i]) < 1 {
			continue
		}
		temp_cIdName_Decrypted, _ := readDecrypted(hashInput_cIdNameEncryption, cIdNames[i])

		//remove record from master list and merkle tree
		if cIdName_Unencrypted == temp_cIdName_Decrypted {
			outIndex = i
		}
	}

	return outIndex, bytes2HexString(state.Hash())
}

//must delete any records with the same cIdName before adding a new record
func tree_NewRecord(state merkle.Tree, username_Hashed string, password_Hashed string, cIdName_Hashed string,
	cIdName_Encrypted string, cPassword_Encrypted string) {

	mapKey := []byte(path.Join(username_Hashed, password_Hashed))

	//get the newIndex and add it to the master list/create the master list if doesn't exist
	if state.Has(mapKey) {
		_, mapValues, _ := state.Get(mapKey)
		state.Set(mapKey, []byte(string(mapValues)+cIdName_Encrypted+"/"))
	} else {
		state.Set([]byte(mapKey), []byte("/"+cIdName_Encrypted+"/"))
	}

	//create the new record in the tree
	insertKey := []byte(path.Join(username_Hashed, password_Hashed, cIdName_Hashed))
	insertValues := []byte(cPassword_Encrypted)
	state.Set(insertKey, insertValues)
}

//read and decrypt from the hashPasswordList
func readDecrypted(hashInput string, encryptedString string) (decryptedString string, err error) {

	// The key length must be 32, 24, or 16  bytes
	key := getHash(hashInput)
	var ciphertext, decryptedByte []byte

	ciphertext, err = hex.DecodeString(encryptedString)
	decryptedByte, err = decrypt(key, ciphertext)
	decryptedString = string(decryptedByte[:])

	return
}

//return an encrypted string. the encyption key is taken as hashed value of the input variable hashInput
func getEncryptedHexString(hashInput string, unencryptedString string) string {

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
