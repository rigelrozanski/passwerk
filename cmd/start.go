package cmd

import (
	"flag"
	"fmt"
	"path"
	"sync"

	cmn "github.com/rigelrozanski/passwerk/common"
	pwkTMSP "github.com/rigelrozanski/passwerk/tmsp"
	tre "github.com/rigelrozanski/passwerk/tree"
	"github.com/rigelrozanski/passwerk/ui"

	"github.com/spf13/cobra"
	. "github.com/tendermint/go-common"
	dbm "github.com/tendermint/go-db"
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
	dBKeyMerkleHash := []byte(cmn.DBKeyMerkleHash)

	//setup the persistent merkle tree to be used by both the UI and TMSP
	oldDBNotPresent, _ := cmn.IsDirEmpty(path.Join(dBPath, dBName) + ".db")

	if oldDBNotPresent {
		fmt.Println("no existing db, creating new db")
	} else {
		fmt.Println("loading existing db")
	}

	//open the db, if the db doesn't exist it will be created
	pwkDB := dbm.NewDB(dBName, dbm.DBBackendLevelDB, dBPath)

	var state merkle.Tree
	state = merkle.NewIAVLTree(cacheSize, pwkDB)

	//either load, or set and load the merkle state
	if oldDBNotPresent {
		pwkDB.Set(dBKeyMerkleHash, state.Save())
	}
	state.Load(pwkDB.Get([]byte(dBKeyMerkleHash)))

	//define the pwkTree which will be fed into UI and TMSP
	//pwkTree will be limited to read only when fed into the UI
	pwkTree := tre.NewPwkMerkleTree(state, cacheSize, pwkDB)

	var pR tre.TreeReading = pwkTree
	var pW tre.TreeWriting = pwkTree

	//define the readers and writers for UI and TMSP respectively
	ptr := tre.NewPwkTreeReader(pR, "", "", "", "") //initilize blank reader variables, updated in UI
	ptw := tre.NewPwkTreeWriter(pW, "", "", "")     //initilize blank reader variables, updated in TMSP

	////////////////////////////////////
	//  Start UI
	go ui.HTTPListener(mu, ptr, portUI, false) //start on a seperate Thread

	////////////////////////////////////
	//  Start TMSP

	// Start the listener
	_, err := server.NewServer(*addrPtr, *tmspPtr, pwkTMSP.NewPasswerkApplication(mu, ptw))

	if err != nil {
		Exit(err.Error())
	}

	// Wait forever
	TrapSignal(func() {
		pwkDB.Close()
	})
}
