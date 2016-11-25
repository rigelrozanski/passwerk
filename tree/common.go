//common functions between reading and writing to trees
package tree

import (
	"path"
)

//////////////////////////////////////////
///   Merkle Key Retrieval
//////////////////////////////////////////

//to prevent key-value collisions in the database that holds
//  records for both the momma-tree and sub-trees, prefixes
//  are added to the keys of all the merkleTree Records
//  For the sub tree values, there is an additional prefix
//  of the hex-string of the hash of username/password
const keyPrefix4SubTree string = "S"
const keyPrefix4SubTreeValue string = "V"

//momma-tree key for record containing the hash for the subtree
func getMapKey(usernameHashed, passwordHashed string) []byte {
	return []byte(path.Join(keyPrefix4SubTree, usernameHashed, passwordHashed))
}

//subtree key for the record which holds the list of password identifiers (cId's)
func GetCIdListKey(usernameHashed, passwordHashed string) []byte {
	return []byte(path.Join(keyPrefix4SubTreeValue, usernameHashed, passwordHashed))
}

//subtree key for a record and password combination
func GetRecordKey(usernameHashed, passwordHashed, cIdNameHashed string) []byte {
	return []byte(path.Join(keyPrefix4SubTreeValue, usernameHashed, passwordHashed, cIdNameHashed))
}
