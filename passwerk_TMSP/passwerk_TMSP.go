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
	"strconv"
	"strings"
	"time"

	. "github.com/tendermint/go-common"
	"github.com/tendermint/go-merkle"
	"github.com/tendermint/tmsp/types"
)

//<incomplete code> should be reprogrammed to not include a maximum <becomes irrelavant when replaced with a merkle-tree structure>
const maxViewableSavedPasswords int = 1000 //maximum amount of stored records <becomes irrelavant when replaced with merkle-tree structure>
const port_passwerkUI string = "8080"
const port_tendermint string = "46657"

// Global Memory Storage Bank <incomplete code> replace with merkle-tree structure instread of array
//[1][] - Hashed Username
//[2][] - Hashed Password
//[3][] - Hash cipherable IdName
//[4][] - Hash cipherable password
var hashPasswordLists [4][maxViewableSavedPasswords]string

type PasswerkApplication struct {
	//currently the merkle-tree stores a list of transactions,
	// this should be upgraded to store the information
	// currently held in hashPasswordLists
	state merkle.Tree
}

func NewPasswerkApplication() *PasswerkApplication {
	go httpListener()
	state := merkle.NewIAVLTree(0, nil)

	return &PasswerkApplication{state: state}
}

func httpListener() {
	http.HandleFunc("/", inputHandler)
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

	//the Merkle tree is simply set to pair of information: index int // tx string
	app.state.Set([]byte(strconv.Itoa(app.state.Size())), tx)

	//seperate the tx into all the parts to be written
	parts := strings.Split(string(tx), "/")

	//The number of parts in the TX are verified upstream within CheckTx
	operationalOption := parts[1] //part[0] contains the timeStamp which is currently ignored (used to avoid duplicate tx submissions)

	switch operationalOption {
	case "writing":

		username_HashedHex := parts[2]
		password_HashedHex := parts[3]
		cIdName_Encrypted := parts[4]
		cPassword_Encrypted := parts[5]

		//write the actual entries
		operatingIndex := getfirstEmptySpaceIndex()
		hashPasswordLists[0][operatingIndex] = username_HashedHex
		hashPasswordLists[1][operatingIndex] = password_HashedHex
		hashPasswordLists[2][operatingIndex] = cIdName_Encrypted
		hashPasswordLists[3][operatingIndex] = cPassword_Encrypted
	case "deleting":

		operatingIndex, _ := strconv.Atoi(parts[2]) //<sloppy code> add error checking
		for i := 0; i < 4; i++ {
			hashPasswordLists[i][operatingIndex] = ""
		}
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
		if len(parts) < 6 {
			return badReturn("Invalid number of TX parts")
		}
	case "deleting":
		if len(parts) < 3 {
			return badReturn("Invalid number of TX parts")
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
func inputHandler(w http.ResponseWriter, r *http.Request) {

	UIoutput := "" //variable which holds the final output to be written by the program
	urlString := r.URL.Path[1:]
	urlStringSplit := strings.Split(urlString, `/`)

	if len(urlStringSplit) >= 3 {

		notSelected := "<notSelected>" //text indicating that a piece of URL input has not been submitted
		speachBubble := "i h8 myslf"   //speach bubble text for the ASCII assailant
		idNameList := ""               //list of all the stored records which will be output if requested by the user (reading_IdNames)
		URL_optionText := notSelected  //1st URL section - <manditory>  indicates the user write mode
		URL_username := notSelected    //2nd URL section - <manditory> master username to be read or written from
		URL_password := notSelected    //3rd URL section - <manditory> master password to be read or written with
		URL_cIdName := notSelected     //4th URL section - <optional> cipherable indicator name for the password
		URL_cPassword := notSelected   //5th URL section - <optional> cipherable password to be stored

		//--------------------------
		//  reading inputs from URL
		//--------------------------

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
		HashInput_idNameEncryption := URL_username + URL_password
		HashInput_storedPasswordEncryption := URL_cIdName + URL_password + URL_username

		var operationalOption string

		switch URL_optionText {
		case "r":
			operationalOption = "reading_IdNames"
			if URL_cIdName != notSelected {
				operationalOption = "reading_Password"
			}
			if URL_username == notSelected ||
				URL_password == notSelected {
				operationalOption = "ERROR_General"
			}

		case "w":
			operationalOption = "writing"
			if URL_cIdName == notSelected ||
				URL_username == notSelected ||
				URL_password == notSelected {
				operationalOption = "ERROR_General"
			}

		case "d":
			operationalOption = "deleting"
			if URL_cIdName == notSelected ||
				URL_username == notSelected ||
				URL_password == notSelected {
				operationalOption = "ERROR_General"
			}

		default:
			operationalOption = "ERROR_General"
		}

		//performing authentication (don't need to authenicate for writing passwords)
		if operationalOption != "writing" && authenicate(URL_username, URL_password) == false {
			operationalOption = "ERROR_Authentication"
		}

		// performing operation
		switch operationalOption {
		case "reading_IdNames": //  <sloppy code> consider moving this section to query

			idNameListArray := getIdNameList(HashInput_idNameEncryption, URL_username, URL_password)
			speachBubble = "...psst down at my toes"

			for i := 0; i < len(idNameListArray); i++ {
				if idNameListArray[i] == "" {
					break
				}
				idNameList = idNameList + `
						` + idNameListArray[i]
			}

		case "reading_Password": // <sloppy code> consider moving this section to query

			operatingIndex := getIdNameIndex(getHashedHexString(URL_username),
				getHashedHexString(URL_password),
				HashInput_idNameEncryption, URL_cIdName)

			if operatingIndex >= 0 {
				speachBubble, _ = readDecryptedFromList(HashInput_storedPasswordEncryption, 3, operatingIndex) //<sloppy code> add error handling
			} else {
				operationalOption = "ERROR_InvalidIdName"
			}

		case "deleting":
			//determine the operation index
			operatingIndex := getIdNameIndex(getHashedHexString(URL_username),
				getHashedHexString(URL_password),
				HashInput_idNameEncryption, URL_cIdName)
			if operatingIndex >= 0 {

				//create he tx then broadcast
				tx2broadcast := timeStampString()
				tx2broadcast += "/" + operationalOption
				tx2broadcast += "/" + strconv.Itoa(operatingIndex)
				broadcastTx_fromString(tx2broadcast)

				speachBubble = "*Chuckles* - nvr heard of no " + URL_cIdName + " before"
			} else {
				operationalOption = "ERROR_InvalidIdName"
			}

		case "writing":
			//before writing, any duplicate records must first be deleted
			//determine the operation index
			operatingIndex := getIdNameIndex(getHashedHexString(URL_username),
				getHashedHexString(URL_password),
				HashInput_idNameEncryption, URL_cIdName)
			if operatingIndex >= 0 {
				//create he tx then broadcast
				tx2broadcast := timeStampString()
				tx2broadcast += "/" + "deleting"
				tx2broadcast += "/" + strconv.Itoa(operatingIndex)
				broadcastTx_fromString(tx2broadcast)
			}

			//now write the records
			//create he tx then broadcast
			tx2broadcast := timeStampString()
			tx2broadcast += "/" + operationalOption
			tx2broadcast += "/" + getHashedHexString(URL_username)
			tx2broadcast += "/" + getHashedHexString(URL_password)
			tx2broadcast += "/" + getEncryptedHexString(HashInput_idNameEncryption, URL_cIdName)
			tx2broadcast += "/" + getEncryptedHexString(HashInput_storedPasswordEncryption, URL_cPassword)
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

		//--------------------------
		//Writing output
		//--------------------------
		UIoutput = "passwerk" + `
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

	fmt.Fprintf(w, UIoutput)
}

func timeStampString() string {
	return time.Now().Format(time.StampMicro)
}

//does the username and password exist somewhere else within the hashPassowordLists array?
func authenicate(username string, password string) bool {

	auth := false
	for i := 0; i < len(hashPasswordLists[0]); i++ {

		if getHashedHexString(username) == hashPasswordLists[0][i] &&
			getHashedHexString(password) == hashPasswordLists[1][i] {
			auth = true
			break
		}
	}

	return auth
}

//determines the first unused space within the array
//once switched to database storage, this method would become irrelavant
func getfirstEmptySpaceIndex() int {
	firstEmptySpaceIndex := -1

	for i := 0; i < len(hashPasswordLists[0]); i++ {
		if hashPasswordLists[0][i] == "" {
			firstEmptySpaceIndex = i
			break
		}
	}

	return firstEmptySpaceIndex
}

//gets the array index in hashPasswordLists containing the matching record for hashed username, password, and cIdName
func getIdNameIndex(username_HashedHex string, password_HashedHex string, hashInput_cIdNameEncryption string, cIdName string) int {

	outputIndex := -1

	for i := 0; i < len(hashPasswordLists[0]); i++ {
		cIdName_decrypted, err := readDecryptedFromList(hashInput_cIdNameEncryption, 2, i)
		if err == nil {
			if username_HashedHex == hashPasswordLists[0][i] &&
				password_HashedHex == hashPasswordLists[1][i] &&
				cIdName == cIdName_decrypted {

				outputIndex = i
			}
		}
	}
	return outputIndex
}

//gets the decrypted list of all of the cIdName records contained under username and password provided
func getIdNameList(hashInput string, username string, password string) [maxViewableSavedPasswords]string {
	var outputString [maxViewableSavedPasswords]string

	var workingOutputIndex int = 0
	for i := 0; i < len(hashPasswordLists[0]); i++ {
		if getHashedHexString(username) == hashPasswordLists[0][i] &&
			getHashedHexString(password) == hashPasswordLists[1][i] {

			var err error
			outputString[workingOutputIndex], err = readDecryptedFromList(hashInput, 2, i)
			if err != nil {
				break
			}

			workingOutputIndex += 1
		}
	}
	return outputString
}

//read and decrypt from the hashPasswordList
func readDecryptedFromList(hashInput string, listCol int, listRow int) (decryptedString string, err error) {

	// The key length must be 32, 24, or 16  bytes
	key := getHash(hashInput)
	var ciphertext, decryptedByte []byte

	ciphertext, err = hex.DecodeString(hashPasswordLists[listCol][listRow])

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

//return datainput as a hex string after it has been hashed
func getHashedHexString(dataInput string) string {

	//performing the hash
	hashBytes := getHash(dataInput)

	//encoding to a hex string, within data the [x]byte array sliced to []byte (shorthand for h[0:len(h)])
	hashHexString := hex.EncodeToString(hashBytes[:])
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
