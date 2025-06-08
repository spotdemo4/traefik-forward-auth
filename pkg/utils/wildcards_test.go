package utils

import (
	"testing"
)

func TestReplaceWildcards(t *testing.T) {
	tests := []struct {
		name     string
		template string
		actual   string
		want     string
	}{
		{
			name:     "Simple domain match",
			template: "test.*.com",
			actual:   "test.example.com",
			want:     "test.example.com",
		},
		{
			name:     "Domain with port",
			template: "test.local:*",
			actual:   "test.local:8080",
			want:     "test.local:8080",
		},
		{
			name:     "IPv4 with port",
			template: "200.*.*.*:*",
			actual:   "192.96.218.131:9232",
			want:     "200.96.218.131:9232",
		},
		{
			name:     "IPv6 with port",
			template: "*:*:*:*:*:*:*:0001:80",
			actual:   "2001:0db8:85a3:0000:0000:8a2e:0370:7334:80",
			want:     "2001:0db8:85a3:0000:0000:8a2e:0370:0001:80",
		},
		{
			name:     "Exact match without wildcards",
			template: "example.com",
			actual:   "example.com",
			want:     "example.com",
		},
		{
			name:     "Unmatched front ignored",
			template: "*.example.com",
			actual:   "abc.def.example.com",
			want:     "def.example.com",
		},
		{
			name:     "Overload front include",
			template: "test.*.example.com",
			actual:   "def.example.com",
			want:     "test.def.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ReplaceWildcards(tt.template, tt.actual)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
