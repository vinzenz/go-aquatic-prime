package aquatic_test

import (
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/vinzenz/go-aquatic-prime"
)

const publicKeyString = `0xAAD0DC5705017D4AA1CD3FA194771E97B263E68308DC09D3D9297247D175CCD05DFE410B9426D3C8019BA6B92D34F21B454D8D8AC8CAD2FB37850987C02592012D658911442C27F4D9B050CFA3F7C07FF81CFEEBE33E1E43595B2ACCC2019DC7247829017A91D40020F9D8BF67300CE744263B4F34FF42E3A7BE3CF37C4004EB`

var pubKey *rsa.PublicKey

func init() {
	// How to initialize the public key
	pubKey = &rsa.PublicKey{
		E: 3, // This is a constant in Aquatic Prime
		N: new(big.Int),
	}
	pubKey.N.SetString(publicKeyString, 0)
}

const exampleLicense = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Email</key>
	<string>user@email.com</string>
	<key>Name</key>
	<string>User</string>
	<key>Signature</key>
	<data>
	Nhe6U/8XCMm7/+2OIzrHjcOsYHNZTg4k8nTajp1dTb+pU5H1cybgQzUJYA1n3IIQAbWe
	qD7a48WFqbzC3powTk6x42b+WpH6boe+u7LW4AXo2ZqGPasVlr1/lUWVHvt5J0OI9oR7
	vmzdXHbbQD7RPXp0ezttrKBFHxNNCbJHMr0=
	</data>
</dict>
</plist>
`

func Example_verifyALicense() {
	if license, err := aquatic.LoadLicenseFromString(exampleLicense); err == nil {
		if err = license.Verify(pubKey); err == nil {
			fmt.Printf("This is a valid license for: %s with email: %s\n", license.GetField("Name"), license.GetField("Email"))
		}
	}
}
