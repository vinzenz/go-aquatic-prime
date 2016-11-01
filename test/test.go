package main

import (
	"crypto/rsa"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/vinzenz/go-aquatic-prime"
)

const (
	pubKey = `0xAAD0DC5705017D4AA1CD3FA194771E97B263E68308DC09D3D9297247D175CCD05DFE410B9426D3C8019BA6B92D34F21B454D8D8AC8CAD2FB37850987C02592012D658911442C27F4D9B050CFA3F7C07FF81CFEEBE33E1E43595B2ACCC2019DC7247829017A91D40020F9D8BF67300CE744263B4F34FF42E3A7BE3CF37C4004EB`

//	privKey = `0x71E092E4AE00FE31C1337FC10DA4BF0FCC4299ACB092B137E61BA185364E888AE9542B5D0D6F37DAABBD19D0C8CDF6BCD8DE5E5C85DC8CA77A58B1052AC3B6AA5C7EA2E58BD484050184D2E241CFCB1D6AB4AC8617499056060833D8F6699B9C54E3BAA36123AFD5B4DDE6F2ADFC08F6970C3BA5C80B9A0A04CB6C6B73DD512B`
)

func main() {
	pubkey := &rsa.PublicKey{
		E: 3,
		N: new(big.Int),
	}
	pubkey.N.SetString(pubKey, 0)

	//privkey := rsa.PrivateKey{PublicKey: pubkey, D: new(big.Int)}
	//privkey.D.SetString(privKey, 0)

	if files, err := filepath.Glob("./data/*.plist"); err == nil {
		for _, file := range files {
			invalid := strings.Contains(file, "Invalid")
			if f, err := os.Open(file); err == nil {
				if license, err := aquatic.LoadLicense(f); err == nil {
					if err = license.Verify(pubkey); err != nil {
						if !invalid {
							fmt.Printf("FAIL: %s - Verify failed with: %s\n", file, err.Error())
						} else {
							fmt.Printf("SUCCESS: %s - Verified as invalid\n", file)
						}
					} else if invalid {
						fmt.Printf("FAIL: %s - Verify did not fail but was expected to", file)
					} else if !invalid {
						fmt.Printf("SUCCESS: %s - All verifications have passed\n", file)
					}
				} else if !invalid {
					fmt.Printf("FAIL: %s - LoadLicense failed with %s\n", file, err.Error())
				}
			}
		}
	}

}
