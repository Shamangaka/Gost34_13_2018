package main

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"
)

func records(t *testing.T, name string) [][]string {
	t.Helper()
	f, err := os.Open("../resources/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rows [][]string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if l := sc.Text(); l != "" && l[0] != '#' {
			rows = append(rows, strings.Fields(l))
		}
	}
	return rows
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The generator must reproduce the mandatory Appendix A byte for byte.
func TestAppendixA(t *testing.T) {
	src, err := os.Open("../resources/input.bin")
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	var out bytes.Buffer
	initrng(0)
	ShortTestVectors(&out, src)
	want, err := os.ReadFile("../resources/gold.txt")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimRight(out.String(), "\n")
	if exp := strings.TrimRight(string(want), "\n"); got != exp {
		gl, el := strings.Split(got, "\n"), strings.Split(exp, "\n")
		for i := range el {
			if i >= len(gl) || gl[i] != el[i] {
				t.Fatalf("line %d differs from gold.txt", i+1)
			}
		}
		t.Fatal("output longer than gold.txt")
	}
}

// 84 cases from the Appendix B reference code, all 21 key/block combinations.
func TestReferenceKAT(t *testing.T) {
	rows := records(t, "reference_kat.txt")
	for _, f := range rows {
		key, pt, ct := unhex(t, f[2]), unhex(t, f[3]), unhex(t, f[4])
		c, err := NewCipher(key, len(pt))
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(pt))
		c.Encrypt(got, pt)
		if !bytes.Equal(got, ct) {
			t.Errorf("%s/%s: encrypt %x, want %x", f[0], f[1], got, ct)
		}
		c.Decrypt(got, ct)
		if !bytes.Equal(got, pt) {
			t.Errorf("%s/%s: decrypt %x, want %x", f[0], f[1], got, pt)
		}
	}
	if len(rows) != 84 {
		t.Fatalf("%d reference cases, want 84", len(rows))
	}
}

func TestModesKAT(t *testing.T) {
	rows := records(t, "modes_kat.txt")
	for _, f := range rows {
		bits, _ := strconv.Atoi(f[2])
		key, pt, want := unhex(t, f[3]), unhex(t, f[5]), unhex(t, f[6])
		var iv []byte
		if f[4] != "-" {
			iv = unhex(t, f[4])
		}
		c, err := NewCipher(key, bits/8)
		if err != nil {
			t.Fatal(err)
		}
		got, back := make([]byte, len(pt)), make([]byte, len(pt))
		switch f[0] {
		case "ECB":
			NewECBEncrypter(c).CryptBlocks(got, pt)
			NewECBDecrypter(c).CryptBlocks(back, want)
		case "CBC":
			NewCBCEncrypter(c, iv).CryptBlocks(got, pt)
			NewCBCDecrypter(c, iv).CryptBlocks(back, want)
		case "CFB":
			NewCFBEncrypter(c, iv).XORKeyStream(got, pt)
			NewCFBDecrypter(c, iv).XORKeyStream(back, want)
		case "OFB":
			NewOFB(c, iv).XORKeyStream(got, pt)
			NewOFB(c, iv).XORKeyStream(back, want)
		case "CTR":
			NewCTR(c, iv).XORKeyStream(got, pt)
			NewCTR(c, iv).XORKeyStream(back, want)
		default:
			t.Fatalf("unknown mode %s", f[0])
		}
		if !bytes.Equal(got, want) || !bytes.Equal(back, pt) {
			t.Errorf("%s %s/%s: mismatch", f[0], f[1], f[2])
		}
	}
	if len(rows) != 54 {
		t.Fatalf("%d mode cases, want 54", len(rows))
	}
}

// The modes coincide with crypto/cipher's generic CBC/CTR/OFB/CFB.
func TestModesAgainstStdlib(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for _, bs := range []int{16, 32, 64} {
		key := make([]byte, 64)
		iv := make([]byte, bs)
		r.Read(key)
		r.Read(iv)
		c, _ := NewCipher(key, bs)
		pt := make([]byte, 7*bs+5)
		r.Read(pt)
		a, b := make([]byte, len(pt)), make([]byte, len(pt))
		NewCTR(c, iv).XORKeyStream(a, pt)
		cipher.NewCTR(c, iv).XORKeyStream(b, pt)
		if !bytes.Equal(a, b) {
			t.Fatalf("CTR differs (bs=%d)", bs)
		}
		NewOFB(c, iv).XORKeyStream(a, pt)
		cipher.NewOFB(c, iv).XORKeyStream(b, pt)
		if !bytes.Equal(a, b) {
			t.Fatalf("OFB differs (bs=%d)", bs)
		}
		NewCFBEncrypter(c, iv).XORKeyStream(a, pt)
		cipher.NewCFBEncrypter(c, iv).XORKeyStream(b, pt)
		if !bytes.Equal(a, b) {
			t.Fatalf("CFB differs (bs=%d)", bs)
		}
		full := pt[:7*bs]
		NewCBCEncrypter(c, iv).CryptBlocks(a[:len(full)], full)
		cipher.NewCBCEncrypter(c, iv).CryptBlocks(b[:len(full)], full)
		if !bytes.Equal(a[:len(full)], b[:len(full)]) {
			t.Fatalf("CBC differs (bs=%d)", bs)
		}
	}
}

func TestRoundTripAllSizes(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for _, bs := range []int{16, 32, 64} {
		for ks := MINKEYLEN; ks <= MAXKEYLEN; ks += KEYLENSTEP {
			for n := 0; n < 50; n++ {
				key, pt := make([]byte, ks), make([]byte, bs)
				r.Read(key)
				r.Read(pt)
				c, err := NewCipher(key, bs)
				if err != nil {
					t.Fatal(err)
				}
				buf := append([]byte(nil), pt...)
				c.Encrypt(buf, buf)
				c.Decrypt(buf, buf)
				if !bytes.Equal(buf, pt) {
					t.Fatalf("round trip failed for key %d, block %d", ks*8, bs*8)
				}
			}
		}
	}
}

func TestRejectsInvalidParameters(t *testing.T) {
	for _, ks := range []int{0, 16, 31, 40, 144} {
		if _, err := NewCipher(make([]byte, ks), 16); err == nil {
			t.Errorf("%d-byte key accepted", ks)
		}
	}
	for _, bs := range []int{0, 8, 24, 48, 128} {
		if _, err := NewCipher(make([]byte, 32), bs); err == nil {
			t.Errorf("%d-byte block accepted", bs)
		}
		rk := make([]byte, 22*128)
		if Kexp(make([]byte, 32), 32, bs, rk) == nil {
			t.Errorf("Kexp accepted %d-byte block", bs)
		}
	}
}

func TestPadding(t *testing.T) {
	for _, bs := range []int{16, 32, 64} {
		for n := 0; n <= 2*bs; n++ {
			data := bytes.Repeat([]byte{0x80}, n)
			u, err := Unpad(Pad(data, bs), bs)
			if err != nil || !bytes.Equal(u, data) {
				t.Fatalf("padding round trip failed (n=%d)", n)
			}
		}
		if _, err := Unpad(make([]byte, bs), bs); err == nil {
			t.Fatal("block without padding marker accepted")
		}
	}
}
