package cmd

import (
	"flag"
	"fmt"
	"sync"

	cmn "passwerk/common"
	pwkTMSP "passwerk/tmsp"
	"passwerk/ui"

	"github.com/spf13/cobra"
	. "github.com/tendermint/go-common"
	"github.com/tendermint/go-db"
	"github.com/tendermint/go-merkle"
	"github.com/tendermint/tmsp/server"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "start passwerk",
	Long:  "initialize passwerk and wait for tendermint-core to start",
	Run:   startRun,
}

func init() {
	//initilize local flags
	startCmd.Flags().IntVarP(&cacheSize, "cacheSize", "c", 0, "Cache size for momma merkle trees and child trees (default 0)")
	startCmd.Flags().StringVarP(&portUI, "portUI", "p", "8080", "local port for the passwerk application")
	startCmd.Flags().StringVarP(&dBPath, "dBPath", "a", "pwkDB", "relative folder name for the storing the passwerk database(s)")
	startCmd.Flags().StringVarP(&dBName, "dBName", "n", "passwerkDB", "name of the passwerk database being stored")
	//startCmd.Flags().BoolVarP(&newDB, "newDb", "n", false, "force generate a new database when inilitizing")
	RootCmd.AddCommand(startCmd)
}

func startRun(cmd *cobra.Command, args []string) {

	addrPtr := flag.String("addr", "tcp://0.0.0.0:46658", "Listen address")
	tmspPtr := flag.String("tmsp", "socket", "socket | grpc")
	flag.Parse()

	//lock for data access
	var mu = &sync.Mutex{}

	//global flagSet
	flagSet := RootCmd.PersistentFlags()

	/////////////////////////////////////
	//  Load Database
	/////////////////////////////////////

	//Keyz for db values which hold information which isn't the contents of a Merkle tree
	dBKeyMerkleHash := []byte("mommaHash")

	//setup the persistent merkle tree to be used by both the UI and TMSP
	oldDBNotPresent, _ := cmn.IsDirEmpty(dBPath + "/" + dBName + ".db")

	if oldDBNotPresent == true {
		fmt.Println("no existing db, creating new db")
	} else {
		fmt.Println("loading existing db")
	}

	//open the db, if the db doesn't exist it will be created
	passwerkDB := db.NewDB(dBName, db.DBBackendLevelDB, dBPath)

	var state merkle.Tree
	state = merkle.NewIAVLTree(cacheSize, passwerkDB)

	//either load, or set and load the merkle state
	if oldDBNotPresent {
		passwerkDB.Set(dBKeyMerkleHash, state.Save())
	}
	state.Load(passwerkDB.Get([]byte(dBKeyMerkleHash)))

	////////////////////////////////////
	//  Start UI
	////////////////////////////////////

	stateReadOnly := state.(cmn.MerkleTreeReadOnly)
	dBReadOnly := cmn.DBReadOnly{DBFile: passwerkDB,
		DBPath: dBPath,
		DBName: dBName,
	}
	go ui.HTTPListener(mu, flagSet, stateReadOnly, dBReadOnly, dBKeyMerkleHash, cacheSize, portUI) //start on a seperate Thread

	////////////////////////////////////
	//  Start TMSP
	////////////////////////////////////

	// Start the listener
	_, err := server.NewServer(*addrPtr, *tmspPtr, pwkTMSP.NewPasswerkApplication(mu, state, passwerkDB, dBKeyMerkleHash, cacheSize))
	if err != nil {
		Exit(err.Error())
	}

	// Wait forever
	TrapSignal(func() {
		// Cleanup
	})
}
