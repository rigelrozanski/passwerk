package cmd

import (
	"flag"
	"fmt"
	"sync"

	cmn "github.com/rigelrozanski/passwerk/common"
	pwkTMSP "github.com/rigelrozanski/passwerk/tmsp"
	"github.com/rigelrozanski/passwerk/ui"

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
	startCmd.Flags().StringVarP(&dBName, "dBName", "n", "pwkDB", "name of the passwerk database being stored")
	//startCmd.Flags().BoolVarP(&newDB, "newDb", "n", false, "force generate a new database when inilitizing")
	RootCmd.AddCommand(startCmd)
}

func startRun(cmd *cobra.Command, args []string) {

	addrPtr := flag.String("addr", "tcp://0.0.0.0:46658", "Listen address")
	tmspPtr := flag.String("tmsp", "socket", "socket | grpc")
	flag.Parse()

	//lock for data access
	mu := new(sync.Mutex)

	/////////////////////////////////////
	//  Load Database
	/////////////////////////////////////

	//Keyz for db values which hold information which isn't the contents of a Merkle tree
	dBKeyMerkleHash := []byte("mommaHash")

	//setup the persistent merkle tree to be used by both the UI and TMSP
	oldDBNotPresent, _ := cmn.IsDirEmpty(path.Join(dBPath, dBName) + ".db")

	if oldDBNotPresent {
		fmt.Println("no existing db, creating new db")
	} else {
		fmt.Println("loading existing db")
	}

	//open the db, if the db doesn't exist it will be created
	pwkDB := db.NewDB(dBName, db.DBBackendLevelDB, dBPath)

	var state merkle.Tree
	state = merkle.NewIAVLTree(cacheSize, pwkDB)

	//either load, or set and load the merkle state
	if oldDBNotPresent {
		pwkDB.Set(dBKeyMerkleHash, state.Save())
	}
	state.Load(pwkDB.Get([]byte(dBKeyMerkleHash)))

	////////////////////////////////////
	//  Start UI
	////////////////////////////////////

	stateReadOnly := state.(cmn.MerkleTreeReadOnly)
	pwkDBReadOnly := cmn.DBReadOnly{DBFile: pwkDB,
		DBPath: dBPath,
		DBName: dBName,
	}
	go ui.HTTPListener(mu, stateReadOnly, pwkDBReadOnly, dBKeyMerkleHash, cacheSize, portUI) //start on a seperate Thread

	////////////////////////////////////
	//  Start TMSP
	////////////////////////////////////

	// Start the listener
	_, err := server.NewServer(*addrPtr, *tmspPtr, pwkTMSP.NewPasswerkApplication(mu, state, pwkDB, dBKeyMerkleHash, cacheSize))
	if err != nil {
		Exit(err.Error())
	}

	// Wait forever
	TrapSignal(func() {
		// TODO: tear down database
	})
}
