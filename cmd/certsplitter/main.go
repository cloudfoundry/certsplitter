package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
)

func main() {
	log.SetOutput(os.Stderr)
	flag.Parse()

	if len(flag.Args()) < 1 {
		log.Println("must provide path to trusted certificates file")
		printUsage()
		os.Exit(1)
	}

	if len(flag.Args()) < 2 {
		log.Println("must provide path to destination folder")
		printUsage()
		os.Exit(1)
	}

	trustedCertsPath := flag.Args()[0]
	data, err := ioutil.ReadFile(trustedCertsPath)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	outputDir := flag.Args()[1]
	certs := splitCerts(string(data))
	for i, c := range certs {
		filename := path.Join(outputDir, fmt.Sprintf("trusted_ca_%d.crt", i+1))
		err = ioutil.WriteFile(filename, []byte(c), 0600)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
	}

}

func printUsage() {
	log.Println()
	log.Printf("Usage: %s TRUSTED_CERTS_FILE DESTINATION_DIRECTORY\n", filepath.Base(os.Args[0]))
}

func splitCerts(certs string) []string {
	result := strings.SplitAfter(certs, "-----END CERTIFICATE-----")
	for i, cert := range result {
		start := strings.Index(cert, "-----BEGIN CERTIFICATE-----")
		if start > 0 {
			result[i] = cert[start:len(cert)]
		}
	}
	return result[:len(result)-1]
}
