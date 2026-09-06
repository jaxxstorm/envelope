package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAttestorRejectsMutableOrUnownedEnrollment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signing-key")
	if err := os.WriteFile(path, make([]byte, 64), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := immutableRead(path, 64, true); err == nil {
		t.Fatal("mutable key accepted")
	}
	if _, err := immutableRead("relative-key", 64, true); err == nil {
		t.Fatal("relative key accepted")
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := immutableRead(link, 64, true); err == nil {
		t.Fatal("symlink key accepted")
	}
	if err := run(context.Background(), []string{"--unknown"}); err == nil {
		t.Fatal("unknown runtime option accepted")
	}
}
