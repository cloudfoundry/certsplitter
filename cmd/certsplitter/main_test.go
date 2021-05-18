package main_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Certsplitter", func() {
	var (
		certsplitterCmd                                  *exec.Cmd
		trustedCertsDir, trustedCertsPath, certDirectory string
	)

	BeforeEach(func() {
		var err error
		trustedCertsDir = filepath.Join(
			os.Getenv("DIEGO_RELEASE_DIR"),
			"src",
			"code.cloudfoundry.org",
			"certsplitter",
			"cmd",
			"certsplitter",
			"fixtures",
		)
		trustedCertsPath = filepath.Join(trustedCertsDir, "trusted-certs.crt")
		certDirectory, err = ioutil.TempDir("", "certsplitter-test")
		Expect(err).NotTo(HaveOccurred())
		certsplitterCmd = exec.Command(certsplitterPath, trustedCertsPath, certDirectory)
	})

	AfterEach(func() {
		os.RemoveAll(certDirectory)
	})

	Context("when it receives a file with multiple certs", func() {
		It("receives a file of concatencated certs and splits them into separate files", func() {
			err := certsplitterCmd.Run()
			Expect(err).NotTo(HaveOccurred())

			var count int
			err = filepath.Walk(certDirectory, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}

				// Files are walked in lexical order
				count++
				Expect(strings.HasSuffix(filepath.Base(path), fmt.Sprintf("%d.crt", count))).To(BeTrue(), "cert filename does not end with sequence number")
				data, err := ioutil.ReadFile(path)
				Expect(err).NotTo(HaveOccurred())
				Expect(bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----"))).To(BeTrue())
				Expect(bytes.HasSuffix(data, []byte("-----END CERTIFICATE-----\n"))).To(BeTrue(), "cert file does not end in newline")

				block, rest := pem.Decode(data)
				Expect(rest).To(BeEmpty())
				certs, err := x509.ParseCertificates(block.Bytes)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(certs)).To(Equal(1))

				return nil
			})

			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(Equal(2))

		})

		Context("when the input file is json, with an array of entries that are one or more certs", func() {
			BeforeEach(func() {
				trustedCertsPath = filepath.Join(trustedCertsDir, "trusted-certs.json")
				certsplitterCmd = exec.Command(certsplitterPath, trustedCertsPath, certDirectory)
			})

			It("produces a cert file for each certificate in the json file", func() {
				err := certsplitterCmd.Run()
				Expect(err).NotTo(HaveOccurred())

				var count int
				err = filepath.Walk(certDirectory, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return err
					}
					if info.IsDir() {
						return nil
					}

					// Files are walked in lexical order
					count++
					Expect(path).To(BeAnExistingFile())
					data, err := ioutil.ReadFile(path)
					Expect(err).NotTo(HaveOccurred())
					Expect(bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----"))).To(BeTrue())
					Expect(bytes.HasSuffix(data, []byte("-----END CERTIFICATE-----\n"))).To(BeTrue(), "cert file does not end in newline")

					block, rest := pem.Decode(data)
					Expect(rest).To(BeEmpty())
					certs, err := x509.ParseCertificates(block.Bytes)
					Expect(err).NotTo(HaveOccurred())
					Expect(len(certs)).To(Equal(1))

					return nil
				})

				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(4))
			})
		})
	})

	Context("when no input file is specifed", func() {
		BeforeEach(func() {
			certsplitterCmd = exec.Command(certsplitterPath)
		})

		It("exits with a failed exit code", func() {
			err := certsplitterCmd.Run()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(&exec.ExitError{}))
			exitErr := err.(*exec.ExitError)
			Expect(exitErr.Success()).To(BeFalse())
		})

		It("logs an error to stderr", func() {
			output, err := certsplitterCmd.CombinedOutput()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(&exec.ExitError{}))
			Expect(string(output)).To(ContainSubstring("must provide path to trusted certificates file"))
			Expect(string(output)).To(ContainSubstring("Usage: certsplitter"))
		})
	})

	Context("when no output directory is specifed", func() {
		BeforeEach(func() {
			certsplitterCmd = exec.Command(certsplitterPath, "does-not-exist")
		})

		It("exits with a failed exit code", func() {
			err := certsplitterCmd.Run()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(&exec.ExitError{}))
			exitErr := err.(*exec.ExitError)
			Expect(exitErr.Success()).To(BeFalse())
		})

		It("logs an error to stderr", func() {
			output, err := certsplitterCmd.CombinedOutput()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(&exec.ExitError{}))
			Expect(string(output)).To(ContainSubstring("must provide path to destination folder"))
			Expect(string(output)).To(ContainSubstring("Usage: certsplitter"))
		})
	})

	Context("when an invalid input file is specified", func() {
		BeforeEach(func() {
			certsplitterCmd = exec.Command(certsplitterPath, "does-not-exist", "does-not-exist")
		})

		It("exits with a failed exit code", func() {
			err := certsplitterCmd.Run()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(&exec.ExitError{}))
			exitErr := err.(*exec.ExitError)
			Expect(exitErr.Success()).To(BeFalse())
		})

		It("logs an error to stderr", func() {
			_, err := certsplitterCmd.CombinedOutput()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(&exec.ExitError{}))
		})
	})

	Context("when the output directory does not exist", func() {
		BeforeEach(func() {
			certsplitterCmd = exec.Command(certsplitterPath, trustedCertsPath, "does-not-exist")
		})

		It("exits with a failed exit code", func() {
			err := certsplitterCmd.Run()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(&exec.ExitError{}))
			exitErr := err.(*exec.ExitError)
			Expect(exitErr.Success()).To(BeFalse())
		})

		It("logs an error to stderr", func() {
			_, err := certsplitterCmd.CombinedOutput()
			Expect(err).To(HaveOccurred())
			Expect(err).To(BeAssignableToTypeOf(&exec.ExitError{}))
		})
	})
})
