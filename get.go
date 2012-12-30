package snmp

import (
	"fmt"

	"github.com/masiulaniec/snmp/mib"
)

// Get retrieves object referenced by (name, value) pairs.
func Get(host, community string, nameval ...interface{}) error {
	switch n := len(nameval); {
	case n == 0:
		return nil
	case n%2 == 1:
		panic("snmp.Get: odd nameval count")
	}
	bindings, err := fromPairs(nameval)
	if err != nil {
		return err
	}
	tr, err := getTransport(host, community)
	if err != nil {
		return err
	}
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
	for i, b := range resp.Bindings {
		if have, want := b.Name, req.Bindings[i].Name; !have.Equal(want) {
			return fmt.Errorf("snmp: %s: get %s: invalid response: name mismatch", host, want)
		}
		v := nameval[2*i+1]
		if err := b.unmarshal(v); err != nil {
			return err
		}
	}
	return nil
}

// fromPairs creates bindings and from the (name, value) pairs.
func fromPairs(nameval []interface{}) ([]Binding, error) {
	var bindings []Binding
	for i := 0; i < len(nameval); i += 2 {
		s, ok := nameval[i].(string)
		if !ok {
			panic("pair name not a string")
		}
		oid, err := mib.Lookup(s)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, Binding{Name: oid})
	}
	return bindings, nil
}
