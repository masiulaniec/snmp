// Package snmp provides read-only SNMPv2 client implementation.
package snmp

import (
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/masiulaniec/snmp/asn1"
	"github.com/masiulaniec/snmp/mib"
)

var nextID = make(chan int32)

func init() {
	rand.Seed(time.Now().UnixNano())
	go func() {
		for {
			nextID <- rand.Int31()
		}
	}()
}

type Request struct {
	Host      string // host or host:port
	Type      string // One of: Get.  Default: Get.
	OID       string // Numeric or textual.
	Community string
}

type message struct {
	Version   int
	Community []byte
	Data      interface{}
}

type pdu struct {
	RequestID   int32
	ErrorStatus int
	ErrorIndex  int
	Bindings    []varBind
}

type varBind struct {
	OID   asn1.ObjectIdentifier
	Value interface{} // asn1.RawValue?
}

func Get(v interface{}, req *Request) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("snmp: %s: get %q: %v", req.Host, req.OID, err)
		}
	}()

	OID, err := mib.Lookup(req.OID)
	if err != nil {
		return
	}
	Community := req.Community
	RequestID := <-nextID
	var request struct {
		Version   int
		Community []byte
		Data      pdu `asn1:"application,tag:0"`
	}
	request.Version = 1
	request.Community = []byte(Community)
	request.Data = pdu{
		RequestID: RequestID,
		Bindings: []varBind{
			{
				OID:   OID,
				Value: asn1.Null{},
			},
		},
	}
	buf, err := asn1.Marshal(request)
	if err != nil {
		return
	}

	hostport := req.Host
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = req.Host + ":161"
	}
	addr, err := net.ResolveUDPAddr("udp", hostport)
	if err != nil {
		return
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return
	}
	if err = conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return
	}
	defer conn.Close()
	if _, err = conn.Write(buf); err != nil {
		return
	}
	buf = make([]byte, 2048, 2048)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return
	}

	var response struct {
		Version   int
		Community []byte
		Data      pdu `asn1:"tag:2"`
	}
	rest, err := asn1.Unmarshal(buf[:n], &response)
	if err != nil {
		return
	}
	if len(rest) != 0 {
		return fmt.Errorf("invalid response: trailing data: %v", rest)
	}
	if response.Version != 1 {
		return fmt.Errorf("invalid response: version is %v", response.Version)
	}
	if !bytes.Equal(response.Community, request.Community) {
		return fmt.Errorf("invalid response: community mismatch")
	}
	if response.Data.RequestID != RequestID {
		return fmt.Errorf("invalid response: ID mismatch")
	}
	if e := response.Data.ErrorStatus; e != 0 {
		return fmt.Errorf("invalid response: server error %v", e)
	}
	switch len(response.Data.Bindings) {
	case 0:
		return fmt.Errorf("invalid response: empty VarBindList")
	case 1:
		// ok
	default:
		return fmt.Errorf("invalid response: extraneous VarBind")
	}
	bind := response.Data.Bindings[0]
	if !bind.OID.Equal(OID) {
		return fmt.Errorf("invalid response: OID mismatch")
	}
	v = bind.Value
	return nil
}
