package snmp

import (
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/masiulaniec/snmp/mib"
)

// Rows is the result of a walk. Its cursor starts before the first
// row of the result set. Use Next to advance through the rows:
//
//     rows, err := snmp.Walk(host, community, "ifName")
//     ...
//     for rows.Next() {
//         var name []byte
//         err = rows.Scan(&name)
//         ...
//     }
//     err = rows.Err() // get any error encountered during iteration
//     ...
type Rows struct {
	row       *row
	Transport RoundTripper
	err       error
}

func Walk(host, community string, oids ...string) (*Rows, error) {
	tr, err := getTransport(host, community)
	if err != nil {
		return nil, err
	}
	row, err := newRow(oids...)
	if err != nil {
		return nil, err
	}
	return &Rows{row: row, Transport: tr}, nil
}

func (rows *Rows) Next() bool {
	if rows.err != nil || rows.row == nil {
		return false
	}
	if err := rows.row.next(rows.Transport); err != nil {
		if err == io.EOF {
			rows.row = nil
		} else {
			rows.err = err
		}
		return false
	}
	return true
}

func (rows *Rows) Scan(v ...interface{}) (interface{}, error) {
	if len(v) != len(rows.row.bindings) {
		panic("Scan: invalid argument count")
	}
	for i, b := range rows.row.bindings {
		if err := b.unmarshal(v[i]); err != nil {
			return nil, err
		}
	}
	return rows.row.instance, nil
}

func (rows *Rows) Err() error {
	return rows.err
}

type row struct {
	// last fetched row
	instance []int
	bindings []Binding

	// the column names
	head []asn1.ObjectIdentifier
}

func newRow(names ...string) (*row, error) {
	r := new(row)
	for _, name := range names {
		oid, err := mib.Lookup(name)
		if err != nil {
			return nil, err
		}
		r.head = append(r.head, oid)
		r.bindings = append(r.bindings, Binding{Name: oid})
	}
	if len(r.head) == 0 {
		panic("no starting oid")
	}
	return r, nil
}

func (r *row) next(tr RoundTripper) error {
	req := &Request{
		Type:     "GetNext",
		Bindings: r.bindings,
		ID:       <-nextID,
	}
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return err
	}
	if err := check(resp, req); err != nil {
		return err
	}
	if err := r.check(resp); err != nil {
		return err
	}
	if !r.inRange(resp.Bindings) {
		return io.EOF
	}
	r.instance = []int(resp.Bindings[0].Name[len(r.head[0]):])
	r.bindings = resp.Bindings
	return nil
}

func (r *row) check(resp *Response) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("invalid response: %v", err)
		}
	}()

	var want []int
	for i, b := range resp.Bindings {
		instance := []int(b.Name[len(r.head[i]):])
		if i == 0 {
			want = instance
			continue
		}
		have := b.Name[len(r.head[i]):]
		if len(have) != len(want) || !hasPrefix(have, want) {
			return fmt.Errorf("inconsistent instances")
		}
	}

	eof := 0
	for i, b := range resp.Bindings {
		if !hasPrefix(b.Name, r.head[i]) {
			eof++
		}
	}
	if eof > 0 && eof != len(r.head) {
		return fmt.Errorf("pre-mature end of a column")
	}

	// TODO: detect non-lexicographic bindings order
	return nil
}

func (r *row) inRange(bindings []Binding) bool {
	for i, b := range bindings {
		if !hasPrefix(b.Name, r.head[i]) {
			return false
		}
	}
	return true
}
