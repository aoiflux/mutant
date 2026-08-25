package server

import "testing"

// The formatter must preserve the compound-assignment and increment/decrement
// spelling rather than expanding it back to `x = x + 1`.
func TestFormatterPreservesCompoundAssignment(t *testing.T) {
	tests := []struct {
		src  string
		want string
	}{
		{"x+=1;", "x += 1;\n"},
		{"x-=1;", "x -= 1;\n"},
		{"x*=2;", "x *= 2;\n"},
		{"x/=2;", "x /= 2;\n"},
		{"x%=2;", "x %= 2;\n"},
		{"x++;", "x++;\n"},
		{"x--;", "x--;\n"},
		// plain assignment is unchanged
		{"x=1;", "x = 1;\n"},
	}

	for _, tt := range tests {
		if got := format(t, tt.src); got != tt.want {
			t.Errorf("format(%q) = %q, want %q", tt.src, got, tt.want)
		}
	}
}
