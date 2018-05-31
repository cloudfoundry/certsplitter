package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	certFileFmt = "trusted-ca-%d.crt"
)

type Certs struct {
	TrustedCACertificates []string `json:"trusted_ca_certificates"`
}

func (c *Certs) fixCerts() {
	allCerts := []string{}
	for _, certs := range c.TrustedCACertificates {
		allCerts = append(allCerts, splitCerts(certs)...)
	}
	c.TrustedCACertificates = allCerts
}

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

	certs := Certs{}
	if strings.Contains(trustedCertsPath, ".json") {
		err := json.Unmarshal(data, &certs)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
	} else {
		certs = Certs{TrustedCACertificates: []string{string(data)}}
	}

	certs.fixCerts()

	outputDir := flag.Args()[1]
	for i, c := range certs.TrustedCACertificates {
		filename := path.Join(outputDir, fmt.Sprintf(certFileFmt, i+1))
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
	chunks := strings.SplitAfter(certs, "-----END CERTIFICATE-----")
	result := []string{}
	for _, chunk := range chunks {
		start := strings.Index(chunk, "-----BEGIN CERTIFICATE-----")
		if start == -1 {
			continue
		}

		cert := chunk[start:len(chunk)] + "\n"
		result = append(result, cert)
	}
	return result
}
