package snmp

import (
	"fmt"
	"encoding/asn1"
	"net"
	"time"

	"github.com/masiulaniec/snmp/mib"
)

// pduGet represents the Get-PDU.
type pduGet struct {
	Version   int
	Community []byte
	Data      pdu `asn1:"application,tag:0"`
}

// Get retrieves the object instance referenced by req and stores it in v, a data
// type supported by encoding/asn1.Unmarshal.
func Get(v interface{}, req *Request) error {
	resp, err := get(req.Host, req.Community, req.OID)
	if err != nil {
		return err
	}
	switch len(resp.Bindings) {
	case 0:
		return fmt.Errorf("invalid response: empty VarBindList")
	case 1:
		// ok
	default:
		return fmt.Errorf("invalid response: extraneous VarBind")
	}
	b := resp.Bindings[0]
	if err = b.check(); err != nil {
		return err
	}
	return unmarshalValue(b.Value, v)
}

// get performs an SNMP Get exchange.
func get(host, community, oid string) (*pdu, error) {
	id := <-nextID
	buf, err := marshal(id, community, oid)
	if err != nil {
		return nil, err
	}
	conn, err := dial(host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err = conn.Write(buf); err != nil {
		return nil, err
	}
	resp, err := unmarshal(conn)
	if err != nil {
		return nil, err
	}
	if err := resp.check(id); err != nil {
		return nil, err
	}
	return &resp.Data, nil
}

// marshal prepares a buf for marshalling.
func marshal(RequestID int32, Community, oid string) ([]byte, error) {
	OID, err := mib.Lookup(oid)
	if err != nil {
		return nil, err
	}
	pdu := pduGet{
		Version:   1,
		Community: []byte(Community),
		Data: pdu{
			RequestID: RequestID,
			Bindings: []varBind{
				{OID: OID, Value: null},
			},
		},
	}
	return asn1.Marshal(pdu)
}
