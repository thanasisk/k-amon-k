package main

import (
	"archive/zip"
	"fmt"
	"os"
	"strings"
)

/*
MD5_BAD := map[string]string {
"04fdd701809d17465c17c7e603b1b202" := "log4j 2.9.0 - 2.11.2"
"21f055b62c15453f0d7970a9d994cab7" := "log4j 2.13.0 - 2.13.3"
MD5_BAD["3bd9f41b89ce4fe8ccbf73e43195a5ce"] := "log4j 2.6 - 2.6.2"
MD5_BAD["415c13e7c8505fb056d540eac29b72fa"] := "log4j 2.7 - 2.8.1"
MD5_BAD["5824711d6c68162eb535cc4dbf7485d3"] := "log4j 2.12.0 - 2.12.1"
MD5_BAD["6b15f42c333ac39abacfeeeb18852a44"] := "log4j 2.1 - 2.3"
MD5_BAD["8b2260b1cce64144f6310876f94b1638"] := "log4j 2.4 - 2.5"
MD5_BAD["a193703904a3f18fb3c90a877eb5c8a7"] := "log4j 2.8.2"
MD5_BAD["f1d630c48928096a484e4b95ccb162a0"] := "log4j 2.14.0 - 2.14.1"
MD5_BAD["5d253e53fa993e122ff012221aa49ec3"] := "log4j 2.15.0"
*/

/*
var MD5_GOOD map[string]string
MD5_GOOD["ba1cf8f81e7b31c709768561ba8ab558"] := "log4j 2.16.0"
*/
func main() {
	fmt.Println("yet another log4j scanner")
	if len(os.Args) != 2 {
		fmt.Println("Usage: %s foo.{jar|war|ear}", os.Args[0])
		os.Exit(-1)
	}
	candidate := os.Args[1]
	// some sanity checks thus candidate status for now
	// filename?
	allowed_exts := [3]string{"jar", "war", "ear"}
	valid := false
	for _, ext := range allowed_exts {
		if strings.HasSuffix(strings.ToLower(candidate), ext) {
			valid = true
			break
		}
	}
	if valid == true {
		fmt.Println("Processing seemingly valid file %s", candidate)
	} else {
		fmt.Println("Invalid file %s", candidate)
		os.Exit(-2)
	}
	process(candidate)
}

func process(fname string) {
	zf, err := zip.OpenReader(fname)
	if err != nil {
		fmt.Println("Invalid Zip Format %s", err)
		os.Exit(-3)
	}
	//h := md5.New()
	for _, f := range zf.File {
		if strings.HasSuffix(f.Name, ".class") {
			fmt.Println(f.Name)
		}
		//if _, err := io.Copy(h,
	}
	defer zf.Close()
	//if _, err := io.Copy(h, f); err != nil {
	//	log.Fatal(err)
	//}

	//fmt.Printf("%x", h.Sum(nil))
}
