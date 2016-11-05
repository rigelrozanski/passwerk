//This package is charged with the user interface and functionality
package common

import (
	"fmt"
	"io"
	"os"
)

//Same as the merkle.Tree Type but without: Set, Remove, Load, Copy
type MerkleTreeReadOnly interface {
	Size() (size int)
	Height() (height int8)
	Has(key []byte) (has bool)
	Get(key []byte) (index int, value []byte, exists bool)
	GetByIndex(index int) (key []byte, value []byte)
	HashWithCount() (hash []byte, count int)
	Hash() (hash []byte)
	Save() (hash []byte)
	Iterate(func(key []byte, value []byte) (stop bool)) (stopped bool)
}

//Same as db.DB but without: Set, SetSync, Delete, DeleteSync, Close
type DBReadOnlyDB interface {
	Get([]byte) []byte
	Print()
}

type DBReadOnly struct {
	DBFile DBReadOnlyDB
	DBPath string
	DBName string
}

/////////////////////////////////
//  File folder operations
/////////////////////////////////

func IsDirEmpty(name string) (bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return true, err //folder is non-existent
	}
	defer f.Close()

	_, err = f.Readdirnames(1) // Or f.Readdir(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err // Either not empty or error, suits both cases
}
func DeleteDir(dir string) error {
	return os.RemoveAll(dir)
}

func CopyDir(source string, dest string) (err error) {

	// get properties of source dir
	sourceinfo, err := os.Stat(source)
	if err != nil {
		return err
	}

	// create dest dir

	err = os.MkdirAll(dest, sourceinfo.Mode())
	if err != nil {
		return err
	}

	directory, _ := os.Open(source)

	objects, err := directory.Readdir(-1)

	for _, obj := range objects {

		sourcefilepointer := source + "/" + obj.Name()

		destinationfilepointer := dest + "/" + obj.Name()

		if obj.IsDir() {
			// create sub-directories - recursively
			err = CopyDir(sourcefilepointer, destinationfilepointer)
			if err != nil {
				fmt.Println(err)
			}
		} else {
			// perform copy
			err = CopyFile(sourcefilepointer, destinationfilepointer)
			if err != nil {
				fmt.Println(err)
			}
		}

	}
	return
}

func CopyFile(source string, dest string) (err error) {
	sourcefile, err := os.Open(source)
	if err != nil {
		return err
	}

	defer sourcefile.Close()

	destfile, err := os.Create(dest)
	if err != nil {
		return err
	}

	defer destfile.Close()

	_, err = io.Copy(destfile, sourcefile)
	if err == nil {
		sourceinfo, err := os.Stat(source)
		if err != nil {
			err = os.Chmod(dest, sourceinfo.Mode())
		}

	}

	return
}
