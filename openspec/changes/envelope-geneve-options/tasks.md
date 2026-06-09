## 1. Configuration & Validation

- [x] 1.1 Add config for option max size, TLV parsing enable flag, and allowlist of option classes/types. Acceptance: flags/env parsed and validated; Test: unit tests for config parsing and invalid values.
- [x] 1.2 Add validation for option length alignment and max size in decode path. Acceptance: malformed/oversized options increment `decap_errors`; Test: unit tests with invalid options lengths.

## 2. Codec & Parsing

- [x] 2.1 Implement optional TLV parser (read-only) for configured option types/classes with zero-copy where possible. Acceptance: selected TLVs extracted without modifying options bytes; Test: unit tests with options containing allowed and disallowed TLVs.
- [x] 2.2 Ensure opaque preserve default remains unchanged when parsing disabled. Acceptance: options bytes are identical on egress; Test: round-trip test with options and parsing disabled.

## 3. Datapath Integration

- [x] 3.1 Wire parsing into ingress path (after validation) and emit structured logs for parsed TLVs. Acceptance: logs show parsed TLVs when enabled; Test: integration/unit test with parsing enabled and fixture options.
- [x] 3.2 Propagate preserved options through flow mapping and egress without mutation. Acceptance: egress options equal ingress options; Test: end-to-end test with options present.

## 4. Tests & Fixtures

- [x] 4.1 Add pcap fixtures with options present and malformed options for validation coverage. Acceptance: fixtures load and tests pass; Test: `go test ./internal/geneve`.
- [x] 4.2 Add datapath tests for options preservation and validation drops. Acceptance: preservation and error counters verified; Test: `go test ./internal/datapath`.

## 5. Documentation

- [x] 5.1 Update README to clarify default opaque preserve behavior and how to enable TLV parsing. Acceptance: docs include defaults and config examples; Test: manual doc review.
