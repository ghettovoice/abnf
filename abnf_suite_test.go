package abnf_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestABNF(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ABNF Suite")
}
