package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The fixture is extracted from the existing gold.txt, itself a transcription
// of Appendix A. It is NOT a separately certified normative source.
func TestV21ProductionKexpVsAppendixA(t *testing.T) {
	file, err := os.Open("testdata/appendix_a_roundkeys_155.tsv")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	type params struct{ keyBits, blockBits int }
	cache := make(map[params][]byte)
	count := 0
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) != 5 {
			t.Fatalf("line %d has %d fields", count+1, len(fields))
		}
		kb, e1 := strconv.Atoi(fields[0])
		bb, e2 := strconv.Atoi(fields[1])
		r, e3 := strconv.Atoi(fields[3])
		key, e4 := hex.DecodeString(fields[2])
		want, e5 := hex.DecodeString(fields[4])
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
			t.Fatalf("invalid fixture on line %d", count+1)
		}
		if kb%8 != 0 || bb%8 != 0 || len(key) != kb/8 || len(want) != bb/8 {
			t.Fatalf("invalid lengths on line %d", count+1)
		}
		p := params{kb, bb}
		rk, present := cache[p]
		if !present {
			rk = make([]byte, RNDS(kb/8)*(bb/8))
			if err := Kexp(key, kb/8, bb/8, rk); err != nil {
				t.Fatalf("production Kexp failed: %v", err)
			}
			cache[p] = rk
		}
		if r < 0 || r >= RNDS(kb/8) {
			t.Fatalf("round out of bounds on line %d", count+1)
		}
		actual := rk[r*(bb/8) : (r+1)*(bb/8)]
		if !bytes.Equal(actual, want) {
			t.Fatalf("K%d/B%d/round%d mismatch: got %x expected %x", kb, bb, r, actual, want)
		}
		count++
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 155 {
		t.Fatalf("checked %d round keys; expected 155", count)
	}
}

func mustPanicAfterReset(t *testing.T, callback func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Error("expected panic after Reset")
		}
	}()
	callback()
}

func TestV21ResetNeverReusesZeroedKey(t *testing.T) {
	for _, bs := range []int{16, 32, 64} {
		c, err := NewCipher(make([]byte, 32), bs)
		if err != nil {
			t.Fatal(err)
		}
		pt := make([]byte, bs)
		ct := make([]byte, bs)
		c.Encrypt(ct, pt)
		c.Reset()
		c.Reset() // idempotence
		for i, v := range c.rkey {
			if v != 0 {
				t.Fatalf("round-key byte %d not zeroed", i)
			}
		}
		mustPanicAfterReset(t, func() { c.Encrypt(ct, pt) })
		mustPanicAfterReset(t, func() { c.Decrypt(pt, ct) })
		if c.BlockSize() != bs {
			t.Fatalf("BlockSize after Reset changed: %d", c.BlockSize())
		}
	}
}
