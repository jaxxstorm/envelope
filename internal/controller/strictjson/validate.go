// Package strictjson validates bounded JSON without materializing its value.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var (
	ErrInvalidLimit          = errors.New("JSON byte limit must be positive")
	ErrTooLarge              = errors.New("JSON input exceeds byte limit")
	ErrMalformed             = errors.New("malformed JSON")
	ErrDuplicateObjectMember = errors.New("duplicate JSON object member")
	ErrTrailingValue         = errors.New("multiple JSON values")
	ErrTrailingData          = errors.New("trailing JSON data")
)

type container struct {
	kind          json.Delim
	expectsMember bool
	members       map[string]struct{}
}

// Validate rejects malformed JSON, duplicate object member names at any
// nesting depth, and content after the first value. Repeated array values are
// allowed. byteLimit bounds both accepted input and token-scanner allocation.
func Validate(payload []byte, byteLimit int) error {
	if byteLimit <= 0 {
		return ErrInvalidLimit
	}
	if len(payload) > byteLimit {
		return fmt.Errorf("%w: maximum %d bytes", ErrTooLarge, byteLimit)
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	stack := make([]container, 0, 8)
	rootStarted := false
	rootComplete := false

	for {
		token, err := decoder.Token()
		if rootComplete {
			switch {
			case errors.Is(err, io.EOF):
				return nil
			case err != nil:
				return fmt.Errorf("%w: %v", ErrTrailingData, err)
			default:
				return ErrTrailingValue
			}
		}
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: unexpected end of input", ErrMalformed)
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrMalformed, err)
		}

		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				if err := consumeValue(stack, &rootStarted); err != nil {
					return err
				}
				frame := container{kind: delimiter}
				if delimiter == '{' {
					frame.expectsMember = true
					frame.members = make(map[string]struct{})
				}
				stack = append(stack, frame)
			case '}', ']':
				if len(stack) == 0 {
					return fmt.Errorf("%w: unexpected closing delimiter", ErrMalformed)
				}
				current := stack[len(stack)-1]
				expected := json.Delim('[')
				if delimiter == '}' {
					expected = '{'
				}
				if current.kind != expected || current.kind == '{' && !current.expectsMember {
					return fmt.Errorf("%w: invalid closing delimiter", ErrMalformed)
				}
				stack = stack[:len(stack)-1]
				if len(stack) == 0 {
					rootComplete = true
				}
			default:
				return fmt.Errorf("%w: unsupported delimiter", ErrMalformed)
			}
			continue
		}

		if len(stack) > 0 {
			current := &stack[len(stack)-1]
			if current.kind == '{' && current.expectsMember {
				member, ok := token.(string)
				if !ok {
					return fmt.Errorf("%w: object member name is not a string", ErrMalformed)
				}
				if _, exists := current.members[member]; exists {
					return ErrDuplicateObjectMember
				}
				current.members[member] = struct{}{}
				current.expectsMember = false
				continue
			}
		}

		if err := consumeValue(stack, &rootStarted); err != nil {
			return err
		}
		if len(stack) == 0 {
			rootComplete = true
		}
	}
}

func consumeValue(stack []container, rootStarted *bool) error {
	if len(stack) == 0 {
		if *rootStarted {
			return ErrTrailingValue
		}
		*rootStarted = true
		return nil
	}

	current := &stack[len(stack)-1]
	if current.kind == '{' {
		if current.expectsMember {
			return fmt.Errorf("%w: object value has no member name", ErrMalformed)
		}
		current.expectsMember = true
	}
	return nil
}
