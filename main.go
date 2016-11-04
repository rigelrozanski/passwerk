//    ____       _      ____    ____                 U _____ u   ____      _  __
//  U|  _"\ uU  /"\  u / __"| u/ __"| u  __        __\| ___"|/U |  _"\ u  |"|/ /
//  \| |_) |/ \/ _ \/ <\___ \/<\___ \/   \"\      /"/ |  _|"   \| |_) |/  | ' /
//   |  __/   / ___ \  u___) | u___) |   /\ \ /\ / /\ | |___    |  _ <  U/| . \\u
//   |_|     /_/   \_\ |____/>>|____/>> U  \ V  V /  U|_____|   |_| \_\   |_|\_\
//   ||>>_    \\    >>  )(  (__))(  (__).-,_\ /\ /_,-.<<   >>   //   \\_,-,>> \\,-.
//  (__)__)  (__)  (__)(__)    (__)      \_)-'  '-(_/(__) (__) (__)  (__)\.)   (_/
//
//  "A cryptographically secure password storage web-utility with distributed consensus using tendermint"
//
//  **for core functionality/usage examples see passwerk/passwerk_TMSP/passwerk_TMSP.go

package main

import (
	"flag"
	"fmt"
	. "github.com/tendermint/go-common"
	"github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
	"github.com/tendermint/tmsp/server"
	"io"
	"os"
	"passwerk/passwerkTMSP"
)

func main() {

	addrPtr := flag.String("addr", "tcp://0.0.0.0:46658", "Listen address")
	tmspPtr := flag.String("tmsp", "socket", "socket | grpc")
	flag.Parse()

	//setup the persistent merkle tree to be used by both the UI and tendermint
	dbPath := "db"
	oldDBNotPresent, _ := IsDirEmpty(dbPath)

	fmt.Println(oldDBNotPresent)

	passwerkDB := db.NewDB("passwerkDB", db.DBBackendLevelDB, dbPath)
	state := merkle.NewIAVLTree(0, passwerkDB) //right now cachesize is set to 0, for production purposes, this should maybe be increased

	//either load, or set and load the dbHash
	merkleHashDBkey := []byte("mommaDBHash")
	if oldDBNotPresent {
		passwerkDB.Set(merkleHashDBkey, state.Save())
	}

	state.Load(passwerkDB.Get([]byte(merkleHashDBkey)))

	// Start the listener
	_, err := server.NewServer(*addrPtr, *tmspPtr, passwerkTMSP.NewPasswerkApplication(state, passwerkDB, merkleHashDBkey))
	if err != nil {
		Exit(err.Error())
	}

	// Wait forever
	TrapSignal(func() {
		// Cleanup
	})
}

func IsDirEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdirnames(1) // Or f.Readdir(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err // Either not empty or error, suits both cases
}
