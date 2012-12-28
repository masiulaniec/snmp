// Package snmp provides an implementation of the SNMP protocol.
package snmp

import (
	"encoding/asn1"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/masiulaniec/snmp/mib"
)

// Request represents a request to SNMP agent.
type Request struct {
	Host      string
	Community string
	OID       string
}

// pdu is the data-carrying part of each packet.
type pdu struct {
	RequestID   int32
	ErrorStatus int
	ErrorIndex  int
	Bindings    []varBind
}

// pduGet represents the Get-PDU.
type pduGet struct {
	Version   int
	Community []byte
	Data      pdu `asn1:"application,tag:0"`
}

// pduResponse represents the Response-PDU.
type pduResponse struct {
	Version   int
	Community []byte
	Data      pdu `asn1:"tag:2"`
}

// check validates the received Response-PDU.
func (resp *pduResponse) check(id int32) error {
	if resp.Version != 1 {
		return fmt.Errorf("invalid response: version is %v", resp.Version)
	}
	if resp.Data.RequestID != id {
		return fmt.Errorf("invalid response: request id mismatch")
	}
	if e := resp.Data.ErrorStatus; e != 0 {
		return fmt.Errorf("invalid response: server error %v", e)
	}
	return nil
}

var (
	null           = asn1.RawValue{Class: 0, Tag: 5}
	noSuchObject   = asn1.RawValue{Class: 2, Tag: 0}
	noSuchInstance = asn1.RawValue{Class: 2, Tag: 1}
	endOfMibView   = asn1.RawValue{Class: 2, Tag: 2}
)

// A varBind binds a value to an OID ("variable").
// In a request, OID identifies an object(s) prefix.
// In a response, OID identifies the object instance.
type varBind struct {
	OID   asn1.ObjectIdentifier
	Value asn1.RawValue
}

// check validates the received varBind.
func (b *varBind) check() error {
	eq := func(a, b asn1.RawValue) bool {
		return a.Class == b.Class && a.Tag == b.Tag
	}
	switch v := b.Value; {
	case eq(v, noSuchObject):
		return fmt.Errorf("no such object")
	case eq(v, noSuchInstance):
		return fmt.Errorf("no such instance")
	case eq(v, endOfMibView):
		return fmt.Errorf("end of mib view")
	case eq(v, null):
		return fmt.Errorf("unexpected null")
	}
	return nil
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

// dial creates a connection to host over UDP.
func dial(host string) (*net.UDPConn, error) {
	hostport := host
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = host + ":161"
	}
	addr, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, err
	}
	if err = conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// unmarshal parses the response message.
func unmarshal(conn *net.UDPConn) (*pduResponse, error) {
	var buf [2048]byte
	n, _, err := conn.ReadFrom(buf[:])
	if err != nil {
		return nil, err
	}
	resp := new(pduResponse)
	if _, err = asn1.Unmarshal(buf[:n], resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// unmarshalValue decodes the varBind's Value.
func unmarshalValue(v asn1.RawValue, out interface{}) error {
	convertType(&v)
	_, err := asn1.Unmarshal(v.FullBytes, out)
	if err != nil {
		if _, ok := err.(asn1.StructuralError); ok {
			return fmt.Errorf("type mismatch: {class:%d tag:%d} vs. %T: %v",
				v.Class, v.Tag, out, err)
		}
		return err
	}
	return nil
}

// convertType enables parsing of SNMP's custom types using the standard
// encoding/asn1 package.
func convertType(v *asn1.RawValue) {
	if v.Class != 1 {
		// Not a custom type.
		return
	}
	switch v.Tag {
	case 0, 4:
		// IpAddress ::= [APPLICATION 0] IMPLICIT OCTET STRING (SIZE (4))
		// Opaque ::= [APPLICATION 4] IMPLICIT OCTET STRING
		v.FullBytes[0] = 0x04
		v.Class = 0
		v.Tag = 4
	case 1, 2, 3:
		// Counter32 ::= [APPLICATION 1] IMPLICIT INTEGER (0..4294967295)
		// Unsigned32 ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295)
		// TimeTicks ::= [APPLICATION 3] IMPLICIT INTEGER (0..4294967295)
		v.FullBytes[0] = 0x02
		v.Class = 0
		v.Tag = 2
	case 6:
		// Counter64 ::= [APPLICATION 6] IMPLICIT INTEGER (0..18446744073709551615)
		v.FullBytes[0] = 0x02
		v.Class = 0
		v.Tag = 2
	}
}

// nextID generates random request IDs.
var nextID = make(chan int32)

func init() {
	rand.Seed(time.Now().UnixNano())
	go func() {
		for {
			nextID <- rand.Int31()
		}
	}()
}
