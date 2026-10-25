// Package blocktools is a thin cgo wrapper over libblocktools_c (secrets-off).
package blocktools

/*
#cgo CFLAGS: -I${SRCDIR}/../../include -I${SRCDIR}/../../../crates/cabi/include
#cgo LDFLAGS: -L${SRCDIR}/../../../target/release -L${SRCDIR}/../../../target/debug -lblocktools_c -Wl,-rpath,${SRCDIR}/../../../target/release
#include "blocktools.h"
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"errors"
	"unsafe"
)

func Version() string { return C.GoString(C.bt_version()) }

func ChainTable() ([]map[string]any, error) {
	p := C.bt_chain_table()
	if p == nil {
		return nil, errors.New("null chain table")
	}
	defer C.bt_free(p)
	var out []map[string]any
	if err := json.Unmarshal([]byte(C.GoString(p)), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func Envelope(req any) (map[string]any, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	cs := C.CString(string(b))
	defer C.free(unsafe.Pointer(cs))
	p := C.bt_envelope(cs)
	if p == nil {
		return nil, errors.New("null envelope")
	}
	defer C.bt_free(p)
	var out map[string]any
	if err := json.Unmarshal([]byte(C.GoString(p)), &out); err != nil {
		return nil, err
	}
	return out, nil
}
