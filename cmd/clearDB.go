package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	cmn "github.com/rigelrozanski/passwerk/common"
)

var clearDBCmd = &cobra.Command{
	Use:   "clearDB",
	Short: "clears the database",
	Long:  "clear the relative database used by passwerk",
	Run:   clearDBRun,
}

func init() {
	//initialize local flags
	clearDBCmd.Flags().StringVarP(&dBPath, "dBPath", "a", "pwkDB", "relative folder name for the storing the passwerk database(s)")
	clearDBCmd.Flags().StringVarP(&dBName, "dBName", "n", "passwerkDB", "name of the passwerk database being stored")

	RootCmd.AddCommand(clearDBCmd)
}

func clearDBRun(cmd *cobra.Command, args []string) {
	fmt.Println("Clearing the DB...")

	err := cmn.DeleteDir(dBName)

	if err != nil {
		fmt.Println(err.Error())
	} else {
		fmt.Println("DB Cleared")
	}
}
