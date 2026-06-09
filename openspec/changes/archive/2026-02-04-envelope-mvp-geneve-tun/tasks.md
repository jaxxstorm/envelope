## 1. Configuration & Wiring

- [x] 1.1 Add config/flags for UDP bind, VNI (optional), TUN name, MTU, and metrics addr with validation. Acceptance: binary starts with explicit config and logs effective settings; Test: unit test config parsing/validation cases.
- [x] 1.2 Create main wiring that starts UDP, TUN, and HTTP servers with clean shutdown. Acceptance: process starts all listeners and exits cleanly on signal; Test: integration test that starts and stops the service.

## 2. GENEVE Codec

- [x] 2.1 Implement minimal GENEVE header parse/serialize (version, header length, VNI, options bytes). Acceptance: round-trip preserves VNI and opaque options; Test: unit tests for parse/serialize with valid inputs.
- [x] 2.2 Add buffer pooling for codec and UDP/TUN I/O buffers. Acceptance: hot-path allocations are avoided in benchmarks; Test: unit test ensures pool reuse on parse/encode paths.
- [x] 2.3 Add codec fixtures: minimal header, header with options, oversized/MTU-related case. Acceptance: all fixtures pass and oversized case fails with explicit error; Test: `go test` for codec package.

## 3. TUN Device

- [x] 3.1 Implement TUN device creation/opening using `golang.org/x/sys/unix`, set MTU, and return file descriptor. Acceptance: `envelope0` appears and is usable for reads/writes; Test: integration test that opens TUN and reads/writes a dummy packet.
- [x] 3.2 Implement TUN read/write loops with pooled buffers. Acceptance: reads/writes are non-blocking under load and return errors cleanly; Test: unit test with mocked reader/writer.

## 4. UDP Datapath

- [x] 4.1 Implement UDP/6081 recv loop that decapsulates GENEVE and writes inner IP to TUN. Acceptance: a valid GENEVE packet results in a TUN write; Test: integration test with a UDP client and TUN reader.
- [x] 4.2 Implement UDP send loop that encapsulates TUN reads and sends to last-seen peer. Acceptance: a TUN packet produces a GENEVE UDP packet to last-seen peer; Test: integration test with UDP server capture.
- [x] 4.3 Implement last-seen peer tracking and drop behavior when missing. Acceptance: egress drops until a peer is seen; Test: unit test for peer tracking and drop counter.

## 5. MTU & Error Handling

- [x] 5.1 Enforce MTU on ingress/egress and count drops/errors. Acceptance: oversized packets are dropped with counters incremented; Test: unit test for MTU enforcement on both paths.
- [x] 5.2 Normalize error handling and logging for malformed headers, TUN/UDP failures. Acceptance: error paths increment counters and log once per error type; Test: unit tests for error paths and counters.

## 6. Observability Endpoints

- [x] 6.1 Add Prometheus counters: `geneve_rx_packets`, `geneve_rx_bytes`, `geneve_tx_packets`, `geneve_tx_bytes`, `decap_errors`, `encap_errors`, `tun_rx_packets`, `tun_tx_packets`, `drops`. Acceptance: `/metrics` exposes all counters; Test: HTTP test that scrapes and verifies names.
- [x] 6.2 Implement `/healthz` on :9090 that reports readiness based on UDP socket and TUN availability. Acceptance: returns 200 only when datapath is ready; Test: HTTP test for ready and not-ready states.

## 7. Test Harness & Docs

- [x] 7.1 Build an end-to-end local test harness (docker-compose acceptable) that replays UDP/6081 traffic, verifies TUN reception, and confirms re-encapsulation. Acceptance: harness produces a deterministic pass/fail signal; Test: run harness in CI/local and assert success.
- [x] 7.2 Update README with local run steps, required Linux capabilities, and MTU guidance. Acceptance: README includes exact commands and capabilities; Test: manual doc review.

## 8. Tailscale MTU Alignment

- [x] 8.1 Set default TUN MTU to 1280 (Tailscale), update README MTU guidance, and align e2e scripts to 1280. Acceptance: defaults and docs reflect 1280; Test: unit test for config default and e2e scripts use 1280.

## 9. GWLB Flow Mapping (Tailscale)

- [x] 9.1 Replace last-seen peer logic with flow-to-peer mapping keyed by inner 5-tuple, including idle timeout sweep. Acceptance: egress uses flow mapping; Test: unit tests for flow table update/lookup/expiry and datapath flow-based egress.
- [x] 9.2 Enforce GENEVE protocol type validation (IPv4/IPv6 only) and drop unsupported types. Acceptance: decap errors increment on invalid protocol; Test: unit test for decap error on unsupported protocol.
- [x] 9.3 Add flow timeout configuration (default 5m) and update README/e2e to describe flow-mapping behavior. Acceptance: config default and docs reflect flow mapping; Test: config unit test and e2e script seeds mapping correctly.
