package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

var exampleCmd = &cobra.Command{
	Use:   "example",
	Short: "provides usage examples",
	Long:  "provides usage examples for passwerk",
	Run:   exampleRun,
}

func init() {
	RootCmd.AddCommand(exampleCmd)
}

func exampleRun(cmd *cobra.Command, args []string) {
	fmt.Println(`
Currently, user input is provided through the URL. 
Output is provided as parsable and fun ASCII art. 
Within the examples HTTP calls, the following variables 
are described as follows:

  masterUsername - The master username that is non-retrievable
  masterPassword - The master password that is non-retrievable
  identifier - a retrievable unique identifier for a saved password
  savedpassword - a retrievable saved password associated with an identifier

The following examples demonstrate the four functions available within passwerk:

  writing a new record to the system:
    http://localhost:8080/w/masterUsername/masterPassword/idenfier/savedpassword

  deleting a saved password/identifier for a given master-username/
  master-password/identifier
    http://localhost:8080/w/masterUsername/masterPassword/idenfier/savedpassword

  retrieve list of identifiers of all the saved passwords for a given 
  master-username/master-password
    http://localhost:8080/w/masterUsername/masterPassword/idenfier/savedpassword

  retrieve a saved password for a given master-username/master-password/identifier
    http://localhost:8080/w/masterUsername/masterPassword/idenfier/savedpassword`)
}
