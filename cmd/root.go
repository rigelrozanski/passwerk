package cmd

import (
	//"flag"
	//"fmt"
	"github.com/spf13/cobra"
)

//flag variables pointed to throughout cmd
var cacheSize int
var portUI, dBPath, dBName string

var RootCmd = &cobra.Command{
	Use:   "passwerk",
	Short: "Save ~passwerds~",
	Long: `
A cryptographically secure password storage web-utility 
with distributed consensus using tendermint
	The following are commands to be used with passwerk:
		start: starts the passwerk program
		clearDB: deletes the database used by passwerk
		example: displays example usage for a running 
			passwerk application
	Additionally flags can be used to specify command 
	parameters, for details on flags please see use help:
		passwerk --help
		passwerk start --help
		passwerk clearDB --help`,
	//The following code can be uncommented if there is any default action for the root cmd, right now there isn't
	//Run: func(cmd *cobra.Command, args []string) {
	//},
}

func init() {
	//persistent flags initialization area (currently none)
}
