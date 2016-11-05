//    ____       _      ____    ____                 U _____ u   ____      _  __
//  U|  _"\ uU  /"\  u / __"| u/ __"| u  __        __\| ___"|/U |  _"\ u  |"|/ /
//  \| |_) |/ \/ _ \/ <\___ \/<\___ \/   \"\      /"/ |  _|"   \| |_) |/  | ' /
//   |  __/   / ___ \  u___) | u___) |   /\ \ /\ / /\ | |___    |  _ <  U/| . \\u
//   |_|     /_/   \_\ |____/>>|____/>> U  \ V  V /  U|_____|   |_| \_\   |_|\_\
//   ||>>_    \\    >>  )(  (__))(  (__).-,_\ /\ /_,-.<<   >>   //   \\_,-,>> \\,-.
//  (__)__)  (__)  (__)(__)    (__)      \_)-'  '-(_/(__) (__) (__)  (__)\.)   (_/
//
//  "A cryptographically secure password storage web-utility with distributed consensus using tendermint"

package main

import (
	"flag"
	"fmt"
	"sync"

	cmn "passwerk/common"
	"passwerk/pwkTMSP"
	"passwerk/ui"

	. "github.com/tendermint/go-common"
	"github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
	"github.com/tendermint/tmsp/server"
)

func main() {

	addrPtr := flag.String("addr", "tcp://0.0.0.0:46658", "Listen address")
	tmspPtr := flag.String("tmsp", "socket", "socket | grpc")
	flag.Parse()

	//lock for data access
	var mu = &sync.Mutex{}

	/////////////////////////////////////
	//  Load Database
	/////////////////////////////////////

	//setup the persistent merkle tree to be used by both the UI and TMSP
	dbPath := "db"
	dbName := "passwerkDB"
	oldDBNotPresent, _ := cmn.IsDirEmpty(dbPath)

	if oldDBNotPresent == true {
		fmt.Println("no existing db, creating new db")
	} else {
		fmt.Println("loading existing db")
	}

	passwerkDB := db.NewDB(dbName, db.DBBackendLevelDB, dbPath)

	var state merkle.Tree
	state = merkle.NewIAVLTree(0, passwerkDB) //right now cachesize is set to 0, for production purposes, this should maybe be increased

	//either load, or set and load the dbHash
	merkleHashDBkey := []byte("mommaDBHash")
	if oldDBNotPresent {
		passwerkDB.Set(merkleHashDBkey, state.Save())
	}

	state.Load(passwerkDB.Get([]byte(merkleHashDBkey)))

	////////////////////////////////////
	//  Start UI
	////////////////////////////////////

	stateReadOnly := state.(cmn.MerkleTreeReadOnly)
	dBReadOnly := cmn.DBReadOnly{DBFile: passwerkDB,
		DBPath: dbPath,
		DBName: dbName,
	}
	go ui.HTTPListener(mu, stateReadOnly, dBReadOnly, merkleHashDBkey)

	////////////////////////////////////
	//  Start TMSP
	////////////////////////////////////

	// Start the listener
	_, err := server.NewServer(*addrPtr, *tmspPtr, pwkTMSP.NewPasswerkApplication(mu, state, passwerkDB, merkleHashDBkey))
	if err != nil {
		Exit(err.Error())
	}

	// Wait forever
	TrapSignal(func() {
		// Cleanup
	})
}
