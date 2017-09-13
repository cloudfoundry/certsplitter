package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gexec"

	"testing"
)

func TestCertsplitter(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Main Suite")
}

var (
	certsplitterPath string
)

var _ = SynchronizedBeforeSuite(func() []byte {
	certsplitter, err := gexec.Build("code.cloudfoundry.org/certsplitter/cmd/certsplitter", "-race")
	Expect(err).NotTo(HaveOccurred())
	return []byte(certsplitter)
}, func(data []byte) {
	certsplitterPath = string(data)
})

var _ = SynchronizedAfterSuite(func() {
}, func() {
	gexec.CleanupBuildArtifacts()
})
