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

	"golang.org/x/sys/unix"
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
		log.Printf("Processing seemingly valid file %s", candidate)
	} else {
		log.Printf("Invalid file %s", candidate)
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
		// Jndi is found
		if strings.HasSuffix(strings.ToLower(f.Name), "jndimanager.class") {
			fc, err := f.Open()
			if err != nil {
				log.Fatal(err)
			}
			defer fc.Close()
			if _, err := io.Copy(h, fc); err != nil {
				log.Fatal(err)
			}
			md5sum := h.Sum(nil)
			if hex.EncodeToString(md5sum[:]) == getGoodMD5() {
				log.Printf("[+] Safe for now: %x\n", md5sum)
			} else if stringInSlice(hex.EncodeToString(md5sum[:]), getBadMD5()) {
				log.Printf("[+] Known BAD MD5 %x\n", md5sum)
			} else {
				log.Printf("[-] UNKNOWN %x - %s\n", md5sum, f.Name)
			}
		} else if strings.HasSuffix(f.Name, ".jar") {
			log.Printf("[+] Nested JAR found! %s", f.Name)
			fc, err := f.Open()
			defer fc.Close()
			if err != nil {
				log.Fatal(err)
			}
			b, err := io.ReadAll(fc)
			tempJAR, err := memfile("tempJAR", b)
			if err != nil {
				log.Fatal(err)
			}
			fp := fmt.Sprintf("/proc/self/fd/%d", tempJAR)
			process(fp)
		}
	}
	defer zf.Close()
}

// Hello Terin! https://terinstock.com/
func memfile(name string, b []byte) (int, error) {
	fd, err := unix.MemfdCreate(name, 0)
	if err != nil {
		return 0, fmt.Errorf("MemfdCreate: %v", err)
	}

	err = unix.Ftruncate(fd, int64(len(b)))
	if err != nil {
		return 0, fmt.Errorf("Ftruncate: %v", err)
	}

	data, err := unix.Mmap(fd, 0, len(b), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return 0, fmt.Errorf("Mmap: %v", err)
	}

	copy(data, b)

	err = unix.Munmap(data)
	if err != nil {
		return 0, fmt.Errorf("Munmap: %v", err)
	}

	return fd, nil
}
