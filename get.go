package snmp

import ()

// Get retrieves object referenced by (name, value) pairs.
func Get(host, community string, nameval ...interface{}) error {
	tr, err := getTransport(host, community)
	if err != nil {
		return err
	}
	// build bindings
	bindings := []Binding{}
	req := &Request{
		Type:     "Get",
		Bindings: bindings,
		ID:       <-nextID,
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return err
	}
	if err := check(resp, req); err != nil {
		return err
	}
	// custom checks
	// b.unmarshal
	return nil
}
