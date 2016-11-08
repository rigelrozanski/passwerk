# passwerk

_A cryptographically secure password storage web-utility with distributed consensus using tendermint_

---

### Installation

1. Make sure you [have Go installed][1] and [put $GOPATH/bin in your $PATH][2]
2. [Install Tendermint Core][3] 
3. Add the contents passwerk to a new folder names passwerk in your [Go src directory][4]
4. Install the passwerk application from the terminal, run `go install passwerk`

[1]: https://golang.org/doc/install
[2]: https://github.com/tendermint/tendermint/wiki/Setting-GOPATH 
[3]: http://tendermint.com/guide/launch-a-tmsp-testnet/
[4]: https://golang.org/doc/code.html#Workspaces
 
### Starting passwerk

1. Initialize a genesis and validator key in ~/.tendermint, run `tendermint init`
2. Within Terminal navigate to the folder where you would like passwerk's database to be stored/read-from (see Notes on Persistence)
3. Within a first Terminal window run `passwerk`
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
The database that Passwerk will either create or read-from is always located in .../db/ where ... is the path you are
navigated to within terminal at the time of execution of the passwerk application. Do not delete or modify  this folder 
while Passwerk is in operation. To clear the database and all records held in a Passwerk instance, you may delete this 
folder and its contents while Passwerk isn't running.
