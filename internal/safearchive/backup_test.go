package safearchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"testing"
)

func archive(t *testing.T, names ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, name := range names {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: 3}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte("abc"))
	}
	tw.Close()
	gz.Close()
	return b.Bytes()
}
func TestRejectsUnsafeOrDuplicatePaths(t *testing.T) {
	for _, names := range [][]string{{"../outside"}, {"/etc/passwd"}, {"a\\..\\outside"}, {"a", "a"}} {
		if err := Validate(bytes.NewReader(archive(t, names...))); err == nil {
			t.Fatalf("accepted %v", names)
		}
	}
}
func TestCRCCheckedBeforeRestore(t *testing.T) {
	b := archive(t, "test.toml")
	b[len(b)-8] ^= 1
	if Validate(bytes.NewReader(b)) == nil {
		t.Fatal("accepted bad checksum")
	}
}
func TestStageReturnsCompleteArchive(t *testing.T) {
	b := archive(t, "tunnel.toml", "acme/key.pem")
	f, err := Stage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	got, _ := io.ReadAll(f)
	if !bytes.Equal(got, b) {
		t.Fatal("staged bytes changed")
	}
}
func TestExpandedSizeLimit(t *testing.T) {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "bomb", Mode: 0600, Size: MaxExpanded + 1})
	tw.Close()
	gz.Close()
	if Validate(bytes.NewReader(b.Bytes())) == nil {
		t.Fatal("accepted oversized entry")
	}
}
