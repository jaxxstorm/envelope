package attestation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeKernelValuesAreReadNotInferred(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ip_forward")
	for _, input := range []string{"1\n", "0\n", "", "true", "1 0", strings.Repeat(" ", 129) + "1"} {
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		if got := kernelValue(path, "1"); got != (input == "1\n") {
			t.Fatalf("kernel value %q accepted=%t", input, got)
		}
	}
	if kernelValue(path+"-missing", "1") {
		t.Fatal("missing kernel value passed")
	}
}
