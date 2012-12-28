// Package snmp provides an implementation of the SNMP protocol.
package snmp

import (
	"encoding/asn1"
	"fmt"
	"math/rand"
	"net"
	"time"
)

var (
	null           = asn1.RawValue{Class: 0, Tag: 5}
	noSuchObject   = asn1.RawValue{Class: 2, Tag: 0}
	noSuchInstance = asn1.RawValue{Class: 2, Tag: 1}
	endOfMibView   = asn1.RawValue{Class: 2, Tag: 2}
)

// Binding represents an assignemnt to a variable, a.k.a. managed object.
type Binding struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}

func (b *Binding) unmarshal(v interface{}) error {
	convertType(&b.Value)
	_, err := asn1.Unmarshal(b.Value.FullBytes, v)
	if err != nil {
		if _, ok := err.(asn1.StructuralError); ok {
			return fmt.Errorf("type mismatch: {class:%d tag:%d} vs. %T: %v",
				b.Value.Class, b.Value.Tag, v, err)
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
	case 1, 2, 3, 6:
		// Counter32 ::= [APPLICATION 1] IMPLICIT INTEGER (0..4294967295)
		// Unsigned32 ::= [APPLICATION 2] IMPLICIT INTEGER (0..4294967295)
		// TimeTicks ::= [APPLICATION 3] IMPLICIT INTEGER (0..4294967295)
		// Counter64 ::= [APPLICATION 6] IMPLICIT INTEGER (0..18446744073709551615)
		v.FullBytes[0] = 0x02
		v.Class = 0
		v.Tag = 2
	}
}

type Request struct {
	ID       int32
	Type     string // "Get", "GetNext"
	Bindings []Binding
}

type Response struct {
	ID          int32
	ErrorStatus int
	ErrorIndex  int
	Bindings    []Binding
}

type RoundTripper interface {
	RoundTrip(*Request) (*Response, error)
}

type Transport struct {
	Conn      net.Conn
	Community string
}

func getTransport(host, community string) (*Transport, error) {
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
	return &Transport{conn, community}, nil
}

func (tr *Transport) RoundTrip(req *Request) (*Response, error) {
	for i := range req.Bindings {
		req.Bindings[i].Value = null
	}
	var buf []byte
	var err error
	switch req.Type {
	case "Get":
		var p struct {
			Version   int
			Community []byte
			Data      struct {
				RequestID   int32
				ErrorStatus int
				ErrorIndex  int
				Bindings    []Binding
			} `asn1:"application,tag:0"`
		}
		p.Version = 1
		p.Community = []byte(tr.Community)
		p.Data.RequestID = req.ID
		p.Data.Bindings = req.Bindings
		buf, err = asn1.Marshal(p)
	case "GetNext":
		var p struct {
			Version   int
			Community []byte
			Data      struct {
				RequestID   int32
				ErrorStatus int
				ErrorIndex  int
				Bindings    []Binding
			} `asn1:"application,tag:1"`
		}
		p.Version = 1
		p.Community = []byte(tr.Community)
		p.Data.RequestID = req.ID
		p.Data.Bindings = req.Bindings
		buf, err = asn1.Marshal(p)
	default:
		panic("unsupported type " + req.Type)
	}
	if err != nil {
		return nil, err
	}
	if _, err := tr.Conn.Write(buf); err != nil {
		return nil, err
	}
	buf = make([]byte, 2048, 2048)
	if err := tr.Conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return nil, err
	}
	n, err := tr.Conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if n == len(buf) {
		return nil, fmt.Errorf("response too big")
	}
	var p struct {
		Version   int
		Community []byte
		Data      struct {
			RequestID   int32
			ErrorStatus int
			ErrorIndex  int
			Bindings    []Binding
		} `asn1:"tag:2"`
	}
	if _, err = asn1.Unmarshal(buf[:n], &p); err != nil {
		return nil, err
	}
	return &Response{p.Data.RequestID, p.Data.ErrorStatus, p.Data.ErrorIndex, p.Data.Bindings}, nil
}

func check(resp *Response, req *Request) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("invalid response: %v", err)
		}
	}()

	if resp.ID != req.ID {
		return fmt.Errorf("id mismatch")
	}

	if e, i := resp.ErrorStatus, resp.ErrorIndex; e != 0 {
		err := fmt.Errorf("server error %v", e)
		if i >= 0 && i < len(resp.Bindings) {
			err = fmt.Errorf("%v: binding %+v", err, resp.Bindings[i])
		}
		return err
	}

	switch n := len(resp.Bindings); {
	case n == 0:
		return fmt.Errorf("no bindings")
	case n < len(req.Bindings):
		return fmt.Errorf("missing bindings")
	case n > len(req.Bindings):
		return fmt.Errorf("extraneous bindings")
	}

	eq := func(a, b asn1.RawValue) bool {
		return a.Class == b.Class && a.Tag == b.Tag
	}
	for _, b := range resp.Bindings {
		switch v := b.Value; {
		case eq(v, noSuchObject):
			return fmt.Errorf("%v: no such object", b.Name)
		case eq(v, noSuchInstance):
			return fmt.Errorf("%v: no such instance", b.Name)
		case eq(v, endOfMibView):
			return fmt.Errorf("%v: end of mib view", b.Name)
		case eq(v, null):
			return fmt.Errorf("%v: unexpected null", b.Name)
		}
	}

	return nil
}

func hasPrefix(instance, prefix []int) bool {
	if len(instance) < len(prefix) {
		return false
	}
	for i := range prefix {
		if instance[i] != prefix[i] {
			return false
		}
	}
	return true
}

// noError(0),
// tooBig(1),
// noSuchName(2),      -- for proxy compatibility
// badValue(3),        -- for proxy compatibility
// readOnly(4),        -- for proxy compatibility
// genErr(5),
// noAccess(6),
// wrongType(7),
// wrongLength(8),
// wrongEncoding(9),
// wrongValue(10),
// noCreation(11),
// inconsistentValue(12),
// resourceUnavailable(13),
// commitFailed(14),
// undoFailed(15),
// authorizationError(16),
// notWritable(17),
// inconsistentName(18)

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
