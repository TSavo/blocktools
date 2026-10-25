package blocktools

import "testing"

func TestVersionAndTable(t *testing.T) {
	v := Version()
	if v == "" || v[0] < '0' || v[0] > '9' {
		t.Fatalf("version %q", v)
	}
	table, err := ChainTable()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range table {
		if c["name"] == "btc" {
			found = true
			if c["buildable"] != true {
				t.Fatalf("btc buildable: %v", c["buildable"])
			}
		}
	}
	if !found {
		t.Fatal("btc missing")
	}
	env, err := Envelope(map[string]any{"op": "chain_table", "chain": "_"})
	if err != nil {
		t.Fatal(err)
	}
	if env["status"] != "ok" {
		t.Fatalf("envelope %v", env)
	}
}
