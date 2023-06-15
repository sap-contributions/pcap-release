package acceptance_tests

import (
	. "github.com/onsi/ginkgo/v2"
)

var _ = Describe("Pcap API Deployment", func() {
	It("Responds to basic requests", func() {

		deployPcap(baseManifestVars{
			deploymentName: deploymentNameForTestNode(),
		}, map[string]interface{}{}, true)

	})
})
