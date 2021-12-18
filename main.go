package main

import (
	"archive/zip"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

func getBadMD5() []string {
	return []string{
		"04fdd701809d17465c17c7e603b1b202",
		"21f055b62c15453f0d7970a9d994cab7",
		"3bd9f41b89ce4fe8ccbf73e43195a5ce",
		"415c13e7c8505fb056d540eac29b72fa",
		"5824711d6c68162eb535cc4dbf7485d3",
		"6b15f42c333ac39abacfeeeb18852a44",
		"8b2260b1cce64144f6310876f94b1638",
		"a193703904a3f18fb3c90a877eb5c8a7",
		"f1d630c48928096a484e4b95ccb162a0",
		"5d253e53fa993e122ff012221aa49ec3",
		"ba1cf8f81e7b31c709768561ba8ab558"}
}

func getGoodMD5() string {
	// 3dc5cf97546007be53b2f3d44028fa58 log4j 2.17.0
	return "3dc5cf97546007be53b2f3d44028fa58"

}
func main() {
	fmt.Println("yet another log4j scanner")
	if len(os.Args) != 2 {
		fmt.Println("Usage: %s foo.{jar|war|ear}", os.Args[0])
		os.Exit(-1)
	}
	candidate := os.Args[1]
	// some sanity checks thus candidate status for now
	// filename?
	allowed_exts := [4]string{"jar", "war", "ear", "zip"}
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

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
func process(fname string) {
	zf, err := zip.OpenReader(fname)
	if err != nil {
		log.Fatal(err)
	}
	h := md5.New()
	for _, f := range zf.File {
		if strings.HasSuffix(f.Name, "JndiManager.class") {
			fc, err := f.Open()
			if err != nil {
				log.Fatal(err)
			}
			//defer f.Close()
			if _, err := io.Copy(h, fc); err != nil {
				log.Fatal(err)
			}
			md5sum := h.Sum(nil)
			fmt.Printf("%x", md5sum)
			if hex.EncodeToString(md5sum[:]) == getGoodMD5() {
				fmt.Printf("\n[+] Safe for now: %x\n", md5sum)
			} else if stringInSlice(hex.EncodeToString(md5sum[:]), getBadMD5()) {
				fmt.Printf("\n[+] Known BAD MD5 %x\n", md5sum)
			} else {
				fmt.Printf("\n[-] UNKNOWN %x\n", md5sum)
			}

		}
		if strings.HasSuffix(f.Name, ".jar") {
			process(f.Name)
		}
	}
	defer zf.Close()
}
