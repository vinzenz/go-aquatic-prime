package aquatic_test

import (
	"crypto/rsa"
	"math/big"
	"os"

	"github.com/vinzenz/go-aquatic-prime"
)

var privKey *rsa.PrivateKey

func init() {
	const publicKeyString = `0xAAD0DC5705017D4AA1CD3FA194771E97B263E68308DC09D3D9297247D175CCD05DFE410B9426D3C8019BA6B92D34F21B454D8D8AC8CAD2FB37850987C02592012D658911442C27F4D9B050CFA3F7C07FF81CFEEBE33E1E43595B2ACCC2019DC7247829017A91D40020F9D8BF67300CE744263B4F34FF42E3A7BE3CF37C4004EB`
	const privateKeyString = `0x71E092E4AE00FE31C1337FC10DA4BF0FCC4299ACB092B137E61BA185364E888AE9542B5D0D6F37DAABBD19D0C8CDF6BCD8DE5E5C85DC8CA77A58B1052AC3B6AA5C7EA2E58BD484050184D2E241CFCB1D6AB4AC8617499056060833D8F6699B9C54E3BAA36123AFD5B4DDE6F2ADFC08F6970C3BA5C80B9A0A04CB6C6B73DD512B`
	// How to initialize a private key
	privKey = &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: 3, // This is a constant in Aquatic Prime
			N: new(big.Int),
		},
		D: new(big.Int),
	}
	privKey.N.SetString(publicKeyString, 0)
	privKey.D.SetString(privateKeyString, 0)
}

func Example_generateALicense() {
	license := aquatic.NewLicense()
	// Add all fields required
	license.SetField("Name", "John Doe")
	license.SetField("Email", "john.doe@example.com")

	// Sign the license
	license.Sign(privKey)

	// Write to any io.Reader
	license.Write(os.Stdout)

	os.Stdout.WriteString("\n")
}
