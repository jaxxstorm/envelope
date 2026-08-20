## 1. Option Model and Configuration

- [x] 1.1 Reconcile option configuration with structural validation and read-only value logging. Acceptance: max size and allowlist inputs use class plus seven-bit type, invalid values fail clearly, and disabling logging does not disable structural validation. Test: `go test ./internal/config -run 'Geneve|TLV'`. Spec: `geneve-tun-datapath` / Optional allocation-free TLV value parsing.
- [x] 1.2 Remove or document any "mapping hint" configuration or behavior. Acceptance: parsed options cannot alter routing or flow selection in this change. Test: code search plus datapath tests showing identical behavior with logging on and off. Spec: `geneve-tun-datapath` / Minimal GENEVE header handling.

## 2. Standards-Correct Parser

- [x] 2.1 Replace full-byte TLV length parsing with low-five-bit length and separate reserved-bit handling. Acceptance: non-zero reserved bits with valid length pass, and malformed bounds fail. Test: `go test ./internal/geneve -run TestTLV`. Spec: `geneve-tun-datapath` / Minimal GENEVE header handling / Reserved option bits.
- [x] 2.2 Implement base and option critical-bit validation. Acceptance: unknown non-critical options pass unchanged; unknown critical options and inconsistent critical indicators fail with specific errors. Test: focused codec/TLV table tests. Spec: `geneve-tun-datapath` / Minimal GENEVE header handling / Unknown critical option.
- [x] 2.3 Replace allocation-heavy parse results on the default path with an iterator or callback. Acceptance: structural validation allocates zero objects per packet when value logging is disabled. Test: `go test -bench=TLV -benchmem ./internal/geneve` with an asserted allocation budget. Spec: `geneve-tun-datapath` / Optional allocation-free TLV value parsing.

## 3. AWS GWLB Options

- [x] 3.1 Add class `0x0108` length/cardinality validation and mandatory flow-cookie extraction independent of the logging allowlist. Acceptance: exactly one flow cookie is required for AWS profile, VPCE/attachment are at most one, wrong shapes fail, and future non-critical AWS types remain opaque. Test: AWS option table tests. Spec: `geneve-tun-datapath` / AWS GWLB option validation.
- [x] 3.2 Ensure logging of allowlisted AWS values is bounded and redacted where required. Acceptance: debug logs identify class/type/length without exposing full flow-cookie or endpoint values by default. Test: observed structured-log tests. Spec: `geneve-tun-datapath` / Optional allocation-free TLV value parsing.

## 4. Fixtures and Datapath Fidelity

- [x] 4.1 Replace or supplement synthetic option PCAPs with sanitized AWS captures or wire-identical fixtures. Acceptance: fixtures contain multiple class `0x0108` options, ordering variations, missing/duplicate cookies, parser-only reserved-bit cases, malformed lengths, and critical cases; fidelity fixtures use zero reserved bits. Test: independent decode script plus `go test ./internal/geneve`. Spec: `geneve-tun-datapath` / AWS-compatible option fixtures.
- [x] 4.2 Assert matching-flow option fidelity end to end. Acceptance: the complete ordered options block, not only parsed values, is byte-identical on matching return traffic. Test: `go test ./internal/datapath -run Options`. Spec: `geneve-tun-datapath` / Minimal GENEVE header handling / Matching return packet preserves options.
- [x] 4.3 Add reason-specific metrics for structural, critical, size, known-AWS-length, and AWS-cardinality rejection. Acceptance: each invalid fixture increments the expected reason and total decapsulation error. Test: datapath metric-value tests. Spec: `geneve-tun-datapath` / AWS GWLB option validation.

## 5. Documentation and Verification

- [x] 5.1 Document opaque ordered preservation, mandatory validation, opt-in value logging, critical semantics, and supported AWS shapes. Acceptance: README no longer says only allowlisted headers are parsed and does not promise mapping hints. Test: documentation review against delta requirements. Spec: all requirements in this change.
- [x] 5.2 Run strict OpenSpec verification and the Go unit/race suites before marking this change complete. Acceptance: every task maps to implementation evidence and all suites pass on Linux. Test: `openspec validate envelope-geneve-options --strict`, `go test ./...`, and `go test -race ./...`. Spec: all requirements in this change.
