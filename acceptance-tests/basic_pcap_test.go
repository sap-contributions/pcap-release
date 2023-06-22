package acceptance_tests

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"os/exec"
	"time"
)

var _ = Describe("Pcap Deployment", func() {
	It("Deploys successfully", func() {

		info, _ := deployPcap(
			baseManifestVars{
				deploymentName: deploymentNameForTestNode(),
			},
			[]string{},
			map[string]interface{}{},
			true,
		)

		err := downloadFile(info, "/var/vcap/packages/pcap-api/bin/cli/build/pcap-bosh-cli-linux-amd64", "/usr/local/bin/pcap-bosh-cli", 0755)
		Expect(err).NotTo(HaveOccurred())

		time.Sleep(2 * time.Hour)

		cmd := exec.Command("which", "pcap-bosh-cli")

		helpTest, err := cmd.Output()
		Expect(err).NotTo(HaveOccurred())

		GinkgoLogr.Info(string(helpTest))

	})
})
