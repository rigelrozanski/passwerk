# passwerk

_A cryptographically secure password storage web-utility with distributed consensus using tendermint_

---

### Installation

1. Make sure you [have Go installed][1] and [put $GOPATH/bin in your $PATH][2]
2. [Install Tendermint Core][3] 
3. [Install Cobra][4]
4. Add the contents passwerk to a new folder names passwerk in your [Go src directory][5]
5. Install the passwerk application from the terminal, run `go install passwerk`

[1]: https://golang.org/doc/install
[2]: https://github.com/tendermint/tendermint/wiki/Setting-GOPATH 
[3]: http://tendermint.com/guide/launch-a-tmsp-testnet/
[4]: https://github.com/spf13/cobra#installing
[5]: https://golang.org/doc/code.html#Workspaces
 
### Starting passwerk

1. Initialize a genesis and validator key in ~/.tendermint, run `tendermint init`
2. Within Terminal navigate to the folder where you would like passwerk's database to be stored/read-from (see Notes on Persistence)
3. Within a first Terminal window run `passwerk start`
	1. flags may be used to specify database/port/cache size etc. for more details run `passwerk start --help` 
4. Within a second Terminal window run `tendermint node`

### Example Usage

Currently, user input is provided through the URL. Output is provided as parsable and fun ASCII art. Within the examples HTTP calls, the following variables are described as follows:
* __masterUsername__ - The master username that is non-retrievable
* __masterPassword__ - The master password that is non-retrievable
* __identifier__ - a retrievable unique identifier for a saved password
* __savedpassword__ - a retrievable saved password associated with an identifier

The following examples demonstrate the four functions available within passwerk:
* writing a new record to the system:  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; http://localhost:8080/w/masterUsername/masterPassword/idenfier/savedpassword  


* deleting a saved password/identifier for a given master-username/master-password/identifier  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; http://localhost:8080/w/masterUsername/masterPassword/idenfier/savedpassword  


* retrieve list of identifiers of all the saved passwords for a given master-username/master-password  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; http://localhost:8080/w/masterUsername/masterPassword/idenfier/savedpassword  


* retrieve a saved password for a given master-username/master-password/identifier  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; http://localhost:8080/w/masterUsername/masterPassword/idenfier/savedpassword

### Notes on Persistence

Passwerk saves its state in a database allowing for the application to resume if it's execution is stopped and restarted.
The database that Passwerk will either create or read-from is by default located in .../pwkDB/ where ... is the path you are
navigated to within terminal at the time of execution of the passwerk application. Do not delete or modify  this folder 
while Passwerk is in operation. To clear the database and all records held in a Passwerk instance, you may delete this 
folder and its contents while Passwerk isn't running. The database name and location may be changed using flags at passwerk 
startup, for more details see `passwerk start --help`

### Command List
  
`passwerk --help` 	diplays program details and command list  
`passwerk start` 	start passwerk, see `passwerk start --help` for addtional startup options  
`passwerk clearDB`	clears the saved db at default location, see `passwerk clearDB --help` for other options  
`passwerk example`	diplays example usage from web browser  

### Testing Code

New code can be tested using the predefined testing packages within passwerk with the suffix "\_test".
All tests can be executed from the passwerk directory with `go test ./...`

### Contributing

1. Fork it
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create new Pull Request

### License

Cobra is released under the Apache 2.0 license.
