package storage

// XRShowConfigsResponse is an element of array
// in xrshowconfig response
type XRShowConfigsResponse struct {
	Pubkey         string            `json:"nodepubkey"`
	PaymentAddress string            `json:"paymentaddress"`
	Config         string            `json:"config"`
	Plugins        map[string]string `json:"plugins"`
}
