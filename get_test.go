package snmp

import (
	"fmt"
	"testing"
)

type GetTest struct {
	oid    string
	expect interface{}
}
var getTests = []GetTest{
	{stringType, []byte(nil)},
	{oidType, []int(nil)},
	{timeticksType, int64(0)},
	{counter32Type, int64(0)},
	{counter64Type, int64(0)},
	{gauge32Type, int64(0)},
}

func TestGetNil(t *testing.T) {
	var v interface{}
	for _, test := range getTests {
		if err := Get("localhost", "public", test.oid, &v); err != nil {
			t.Errorf("%s unexpected error: %v", test.oid, err)
			continue
		}
		have := fmt.Sprintf("%T", v)
		want := fmt.Sprintf("%T", test.expect)
		if have != want {
			t.Errorf("%s bad type, want=%s, have=%s", test.oid, want, have)
		}
	}
}

type HostTest struct {
	host   string
	expect string
}

var hostTests = []string{
	"localhost",
	"localhost:161",
}

func TestHostPort(t *testing.T) {
	var want string
	for i, host := range hostTests {
		var v []byte
		err := Get(&v, &Request{
			Host:      host,
			OID:       stringType,
			Community: "public",
		})
		if err != nil {
			t.Errorf("%s unexpected error: %v", host, err)
		}
		if have := string(v); i == 0 {
			want = have
		} else if have != want {
			t.Errorf("%s wrong host, want=%s, have=%s", host, want, have)
		}
	}
}

type CommunityTest struct {
	str string
	ok  bool
	err error
}

var communityTests = []CommunityTest{
	{str: "", ok: false},
	{str: "public", ok: true},
	{str: "invalid", ok: false},
}

func TestCommunity(t *testing.T) {
	ch := make(chan CommunityTest)
	for _, test := range communityTests {
		str := test.str
		test := test
		go func() {
			var v interface{}
			test.err = Get(&v, &Request{
				Host:      "localhost",
				OID:       stringType,
				Community: str,
			})
			ch <- test
		}()
	}
	for _ = range communityTests {
		test := <-ch
		if (test.err == nil) != test.ok {
			t.Errorf("%s invalid reaction, err=%s", test.str, test.err)
		}
	}
}

type TestRun struct {
	req *Request
}

func TestParallel(t *testing.T) {
	const N = 1000
	done := make(chan bool)
	for i := 0; i < N; i++ {
		go func() {
			var v interface{}
			err := Get(&v, &Request{
				Host:      "localhost",
				OID:       stringType,
				Community: "public",
			})
			if err != nil {
				t.Errorf("%d unexpected error: %v", i, err)
			}
			done <- true
		}()
	}
	for i := 0; i < N; i++ {
		<-done
	}
}
