package strictjson

import (
	"errors"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantErr error
	}{
		{
			name:    "nested objects and repeated array values",
			payload: `{"left":{"id":1},"right":{"id":1},"values":["same","same",1,1,{"id":1},{"id":1}]}`,
		},
		{name: "duplicate root member", payload: `{"id":1,"id":2}`, wantErr: ErrDuplicateObjectMember},
		{name: "duplicate nested member", payload: `{"outer":{"id":1,"id":2}}`, wantErr: ErrDuplicateObjectMember},
		{name: "duplicate escaped member", payload: `{"id":1,"\u0069d":2}`, wantErr: ErrDuplicateObjectMember},
		{name: "malformed object", payload: `{"id":`, wantErr: ErrMalformed},
		{name: "malformed array", payload: `[1,]`, wantErr: ErrMalformed},
		{name: "non-finite NaN", payload: `{"value":NaN}`, wantErr: ErrMalformed},
		{name: "non-finite infinity", payload: `{"value":Infinity}`, wantErr: ErrMalformed},
		{name: "second value", payload: `{} []`, wantErr: ErrTrailingValue},
		{name: "trailing token", payload: `{} nope`, wantErr: ErrTrailingData},
		{name: "empty", payload: ``, wantErr: ErrMalformed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := Validate([]byte(test.payload), 1024)
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Validate() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestValidateBoundsInput(t *testing.T) {
	if err := Validate([]byte(`{}`), 0); !errors.Is(err, ErrInvalidLimit) {
		t.Fatalf("Validate() invalid-limit error = %v", err)
	}
	if err := Validate([]byte(strings.Repeat(" ", 9)), 8); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("Validate() oversize error = %v", err)
	}
}
