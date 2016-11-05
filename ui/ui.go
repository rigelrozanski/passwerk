//This package is charged with the user interface and functionality
package ui

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strings"
	"time"

	cry "passwerk/cryptoMgt"
	tree "passwerk/treeMgt"

	"github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
)

const portPasswerkUI string = "8080"
const portTendermint string = "46657"

type PasswerkApplication struct {
	state        merkle.Tree
	stateDB      db.DB
	stateHashKey []byte
}

func HttpListener(stateIn merkle.Tree, stateDBIn db.DB, stateHashKeyIn []byte) {

	app := &PasswerkApplication{
		state:        stateIn,
		stateDB:      stateDBIn,
		stateHashKey: stateHashKeyIn,
	}

	http.HandleFunc("/", app.UIInputHandler)
	http.ListenAndServe(":"+portPasswerkUI, nil)
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
	//<sloppy code> is there maybe a more secure mechanism to create a shared key equivalent?
	HashInputCIdNameEncryption := path.Join(urlUsername, urlPassword)
	HashInputCPasswordEncryption := path.Join(urlCIdName, urlPassword, urlUsername)

	var operationalOption string
	operationalOption, err = getOperationalOption(notSelected, urlOptionText, urlUsername,
		urlPassword, urlCIdName, urlCPassword)
	if err != nil {
		writeUI()
		return
	}

	//performing authentication (don't need to authenicate for writing passwords)
	if operationalOption != "writing" &&
		tree.Authenticate(app.state, cry.GetHashedHexString(urlUsername), cry.GetHashedHexString(urlPassword)) == false {
		err = errors.New("badAuthentication")
		writeUI()
		return
	}

	// performing operation
	switch operationalOption {
	case "readingIdNames":

		var idNameListArray []string
		idNameListArray, err = tree.RetrieveCIdNames(
			&app.stateDB,
			app.state,
			cry.GetHashedHexString(urlUsername),
			cry.GetHashedHexString(urlPassword),
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
		cPasswordDecrypted, err = tree.RetrieveCPassword(
			&app.stateDB,
			app.state,
			cry.GetHashedHexString(urlUsername),
			cry.GetHashedHexString(urlPassword),
			cry.GetHashedHexString(urlCIdName),
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
		mapCIdNameEncrypted2Delete, err = tree.GetCIdListEncryptedCIdName(
			&app.stateDB,
			app.state,
			cry.GetHashedHexString(urlUsername),
			cry.GetHashedHexString(urlPassword),
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
				cry.GetHashedHexString(urlUsername),
				cry.GetHashedHexString(urlPassword),
				cry.GetHashedHexString(urlCIdName),
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
		mapCIdNameEncrypted2Delete, err = tree.GetCIdListEncryptedCIdName(
			&app.stateDB,
			app.state,
			cry.GetHashedHexString(urlUsername),
			cry.GetHashedHexString(urlPassword),
			urlCIdName,
			HashInputCIdNameEncryption,
		)
		if len(mapCIdNameEncrypted2Delete) >= 0 && err == nil {

			//create he tx then broadcast
			tx2broadcast := path.Join(
				timeStampString(),
				"deleting",
				cry.GetHashedHexString(urlUsername),
				cry.GetHashedHexString(urlPassword),
				cry.GetHashedHexString(urlCIdName),
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
			cry.GetHashedHexString(urlUsername),
			cry.GetHashedHexString(urlPassword),
			cry.GetHashedHexString(urlCIdName),
			cry.GetEncryptedHexString(HashInputCIdNameEncryption, urlCIdName),
			cry.GetEncryptedHexString(HashInputCPasswordEncryption, urlCPassword))
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
	anyAreNotSelected := func(inputs []string) bool {
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
		if anyAreNotSelected([]string{urlUsername, urlPassword}) {
			return "", genErr
		} else if urlCIdName != notSelected {
			return "readingPassword", nil
		} else {
			return "readingIdNames", nil
		}

	case "w":
		if anyAreNotSelected([]string{urlCIdName, urlCPassword, urlUsername, urlPassword}) {
			return "", genErr
		} else {
			return "writing", nil
		}
	case "d":
		if anyAreNotSelected([]string{urlCIdName, urlUsername, urlPassword}) {
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
