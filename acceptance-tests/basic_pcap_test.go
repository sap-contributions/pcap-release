package acceptance_tests

import (
	"fmt"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"math/rand"
	"os/exec"
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

		rnd := rand.New(rand.NewSource(GinkgoRandomSeed()))

		boshCli := fmt.Sprintf("/usr/local/bin/pcap-bosh-cli-%d", rnd.Uint64())

		By("Downloading remote pcap-bosh-cli-linux-amd64 to " + boshCli)
		err := downloadFile(info, "/var/vcap/packages/pcap-api/bin/cli/build/pcap-bosh-cli-linux-amd64", boshCli, 0755)
		Expect(err).NotTo(HaveOccurred())

		cmd := exec.Command(boshCli, "--help")

		helpTest, err := cmd.Output()
		Expect(err).NotTo(HaveOccurred())

		writeLog(string(helpTest))
	})
})
