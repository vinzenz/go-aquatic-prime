// Copyright 2016 Vinzenz Feenstra. All rights reserved.
// Use of this source code is governed by a BSD-2-clause
// license that can be found in the LICENSE file.
package aquatic

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/vinzenz/go-plist"
)

type fieldKeysSorter []string

func (self fieldKeysSorter) Len() int {
	return len(self)
}

func (self fieldKeysSorter) Less(i, j int) bool {
	return strings.ToLower(self[i]) < strings.ToLower(self[j])
}

func (self fieldKeysSorter) Swap(i, j int) {
	self[i], self[j] = self[j], self[i]
}

var (
	// InvalidLicenseFormatError is returned when unsupported elements in the license are found.
	InvalidLicenseFormatError = fmt.Errorf("Invalid license format")
	// InvalidSignatureError is returned when the license is invalid
	InvalidSignatureError = fmt.Errorf("The signature of the license is not valid")
	// CannotModifySignatureError is returned when an attempt to modify the Signature element is detected.
	CannotModifySignatureError = fmt.Errorf("The signature key cannot be modified")
	// MissingSignatureError is returned when no signature can be found.
	MissingSignatureError = fmt.Errorf("The signature key cannot be found")
)

var randSource = rand.Reader

// License gives the possibility to interact with the license key to verify or modify it.
type License struct {
	data map[string]plist.Value
}

func (self License) keys() []string {
	keys := fieldKeysSorter(make([]string, 0, len(self.data)))
	for k, _ := range self.data {
		if k != "Signature" {
			keys = append(keys, k)
		}
	}
	sort.Sort(keys)
	return keys
}

func (self License) hash() []byte {
	hasher := sha1.New()
	for _, k := range self.keys() {
		hasher.Write([]byte(self.data[k].Value.(string)))
	}
	return hasher.Sum(nil)
}

// Creates a new instance of the License, only useful for generating new keys.
func NewLicense() (license *License) {
	return &License{
		data: map[string]plist.Value{
			"Signature": plist.InvalidValue,
		},
	}
}

// GetField retrieves the value of a license key field specified by key.
func (self *License) GetField(key string) string {
	if key != "Signature" {
		if v, ok := self.data[key]; ok {
			return v.Value.(string)
		}
	}
	return ""
}

// SetField sets value of a license key field specified by key.
func (self *License) SetField(key, value string) {
	if key != "Signature" {
		self.data[key] = plist.Value{value, plist.StringType}
	}
}

// DelField removes the field specified by key from the license key.
func (self *License) DelField(key string) error {
	if key != "Signature" {
		if _, ok := self.data[key]; !ok {
			return nil
		}
		delete(self.data, key)
		return nil
	} else {
		return CannotModifySignatureError
	}
}

// Sign signs the current state of the license key with the private key passed in as privKey.
// An successful attempt returns nil an error is returned otherwise.
func (self *License) Sign(privKey *rsa.PrivateKey) error {
	if hash, err := rsa.SignPKCS1v15(nil, privKey, crypto.Hash(0), self.hash()); err != nil {
		return err
	} else {
		self.data["Signature"] = plist.Value{hash, plist.DataType}
	}
	return nil
}

// Write serializes the license key as xml plist to writer. When the license was modified after
// loading it from the file or if this is a newly created license key, Sign needs to be called before
// calling Write to receive a valid license key file.
func (self License) Write(writer io.Writer) error {
	return plist.Value{self.data, plist.DictType}.Write(writer)
}

// Verify uses pubKey to verify the license key data. In case of a valid license nil will be returned.
// If no license key is present MissingSignatureError is returned and if the signature is invalid
// InvalidSignatureError will be returned.
func (self *License) Verify(pubKey *rsa.PublicKey) error {
	if sig, ok := self.data["Signature"]; ok && sig.Type == plist.DataType {
		sigData := sig.Value.([]byte)
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.Hash(0), self.hash(), sigData); err != nil {
			return InvalidSignatureError
		}
		return nil
	}
	return MissingSignatureError
}

// LoadLicenseFromString is a convenience wrapper around LoadLicense to allow loading of a license
// from a string.
func LoadLicenseFromString(data string) (license *License, err error) {
	return LoadLicense(bytes.NewReader([]byte(data)))
}

// LoadLicense loads a license from reader and verifies that the license format is correct. If it is not
// valid an error is returned.
func LoadLicense(reader io.Reader) (license *License, err error) {
	license = new(License)
	var data plist.Value
	data, err = plist.Read(reader)
	if data.Type == plist.DictType {
		license.data = data.Value.(map[string]plist.Value)
		for k, v := range license.data {
			if k == "Signature" {
				if v.Type != plist.DataType {
					return nil, fmt.Errorf("Signature: %s", InvalidLicenseFormatError.Error())
				}
			} else if v.Type != plist.StringType {
				return nil, fmt.Errorf("Field(%s): "+InvalidLicenseFormatError.Error(), k)
			}
		}
	}
	return
}
