package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func getBadSHA256() []string {
	// https://raw.githubusercontent.com/nccgroup/Cyber-Defence/master/Intelligence/CVE-2021-44228/modified-classes/sha256sum.txt
	// sort |uniq
	return []string{
		"01a26cb9062365f7c544a57d2a90a86f178495dd13b3faca3256e69a090eba74",
		"1584b839cfceb33a372bb9e6f704dcea9701fa810a9ba1ad3961615a5b998c32",
		"1fa92c00fa0b305b6bbe6e2ee4b012b588a906a20a05e135cbe64c9d77d676de",
		"293d7e83d4197f0496855f40a7745cfcdd10026dc057dfc1816de57295be88a6",
		"2aef3129ca881726793b206c727981eb5a9e64ab2258a351b04238f3220470be",
		"3bff6b3011112c0b5139a5c3aa5e698ab1531a2f130e86f9e4262dd6018916d7",
		"3d64decc169e316ecf8f10c58d6e010efc77a28b99ba80dd5c0dfaced0ad6d31",
		"3e190fe48eda05d4c17f8944361c68e0e5821abccef5eeeac79d6e06fb8b6337",
		"4b140706f194da9cf1a5c6de4db0210b7b95c2d2f8024cfe53009b68c47a1c4b",
		"4d14a364397b5799d5cd28deab88d0a6603a744dd8e9fb0a6a281f6836e88035",
		"4d545f1590da3062c5a570f3b56ba87f576c698e3c0a623eedaa9452ec322387",
		"59f5acb43e4c05d3ef521a8f308c06c26474ec134cdb58d8dd6b171452f20310",
		"6540d5695ddac8b0a343c2e91d58316cfdbfdc5b99c6f3f91bc381bc6f748246",
		"6ebac1560d176f47389a18a8ab191fc8651a494a2878f963d5c531dd46806973",
		"6fb4422626293c894821100d7b98ab2f8b5e7701e515fec83a59f12f0cd15bcc",
		"764b06686dbe06e3d5f6d15891250ab04073a0d1c357d114b7365c70fa8a7407",
		"77323460255818f4cbfe180141d6001bfb575b429e00a07cbceabd59adf334d6",
		"7c34611f6d076855b19fc8495fc1c31acb36fb514d563c681bc1051ec64ea5f5",
		"9082a3b7ea26325fffb93ecaf81f8b35335f218a6ae076b05b531768eeed5396",
		"9c887fdd72a99a13f1d80b9a8bf1d3ec68509aa1c0c416275fbcf39e2e0ed41e",
		"a0dc96c7695c927682d8d0497624548bad8d8e67d0b1dea5a2f8c142d500683c",
		"ada90fa134c40b4b44c235b7ef52753ce42ed52dc56e3c536c40096f9ff2e40e",
		"ae950f9435c0ef3373d4030e7eff175ee11044e584b7f205b7a9804bbe795f9c",
		"b49948c5b8cf3b18c996036f3cc842a59ea1720c9534dfac616626170d6b3e4e",
		"c3e95da6542945c1a096b308bf65bbd7fcb96e3d201e5a2257d85d4dedc6a078",
		"d352a4a99913ba18e8ee89cb00aa5aff937ea88bcb4caefd15bdb7f94f6d26fa",
		"d5e81e820da0758d41080253eee34e9ab3d78a25525bf060e008f6638e586055",
		"d92121a5a25a3eddc99a907726633ba64432269856d8cd04f99338b070eddd7d",
		"da20205355f3b9ad3fc4402e3046adb47ab1891853566a8a949e6d7dde6ef776",
		"db07ef1ea174e000b379732681bd835cfede648a7971bf4e9a0d31981582d69e",
		"e29effcda5154fd449b62fd06fec5bf26fdbc64239acad179dd955c250672777",
		"ebd5645c843d4b5bf2b409123294eb62d0b659161e6e10a10acdc4aa18537dc3",
		"f5a0e20bbfd40f91946dd6d79d86b9cc7a97000d729d2a0df38ab15450dd8781",
		"f96e82093706592b7c9009c1472f588fc2222835ea808ee2fa3e47185a4eba70",
		"fcc73739eee74adb5b46d1e12ea26ed91d12808cf2021a6d34fcddd7c02aaaf4"}
}

func getGoodSHA256() string {
	// 2.17.0
	//return "db07ef1ea174e000b379732681bd835cfede648a7971bf4e9a0d31981582d69e"
	return "9c2a6ea36c79fa23da59cc0f6c52c07ce54ca145ddd654790a3116d2b24de51b"
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
	h := sha256.New()
	for _, f := range zf.File {
		// Jndi is found
		if strings.HasSuffix(strings.ToLower(f.Name), "jndimanager.class") {
			fc, err := f.Open()
			if err != nil {
				log.Fatal(err)
			}
			defer fc.Close()
			if _, err := io.Copy(h, fc); /* #nosec G110 */ err != nil {
				// a specific file so no DoS likely
				log.Fatal(err)
			}
			checksum := h.Sum(nil)
			if hex.EncodeToString(checksum[:]) == getGoodSHA256() {
				log.Printf("[+] Known GOOD checksum: %x\n", checksum)
			} else if stringInSlice(hex.EncodeToString(checksum[:]), getBadSHA256()) {
				log.Printf("[+] Known BAD checksum %x\n", checksum)
			} else {
				log.Printf("[-] UNKNOWN %x - %s\n", checksum, f.Name)
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
