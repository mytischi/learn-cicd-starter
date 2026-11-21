package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	errMalformedHeader := errors.New("malformed authorization header")

	tests := map[string]struct {
		headers http.Header
		want    string
		wantErr error
	}{
		"valid api key": {
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			want:    "my-secret-key",
			wantErr: nil,
		},
		"extra segments after api key": {
			headers: http.Header{"Authorization": []string{"ApiKey my-secret-key extra"}},
			want:    "my-secret-key",
			wantErr: nil,
		},
		"missing authorization header": {
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"empty authorization header": {
			headers: http.Header{"Authorization": []string{""}},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		"missing key value": {
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			want:    "",
			wantErr: errMalformedHeader,
		},
		"wrong auth scheme": {
			headers: http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			want:    "",
			wantErr: errMalformedHeader,
		},
		"lowercase auth scheme": {
			headers: http.Header{"Authorization": []string{"apikey my-secret-key"}},
			want:    "",
			wantErr: errMalformedHeader,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)

			if tc.wantErr != nil {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if errors.Is(tc.wantErr, ErrNoAuthHeaderIncluded) {
					if !errors.Is(err, ErrNoAuthHeaderIncluded) {
						t.Fatalf("expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
					}
				} else if err.Error() != tc.wantErr.Error() {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err)
				}
			} else if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if got != tc.want {
				t.Fatalf("expected: %q, got: %q", tc.want, got)
			}
		})
	}
}
