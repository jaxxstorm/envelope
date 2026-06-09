## Why

**Motivation:** GWLB deployments rely on GENEVE options for control-plane metadata and flow symmetry. We need consistent end-to-end preservation of options on return traffic, plus bounded validation and optional TLV parsing for logging/mapping, to align with GWLB expectations and reduce ambiguity in troubleshooting.

## What Changes

- Preserve GENEVE options end-to-end by default on return traffic (opaque passthrough).
- Add validation for option length and size bounds to prevent malformed or oversized option blocks.
- Optionally parse selected TLVs for logging and/or flow-mapping hints without modifying the payload.
- Add tests that cover option presence, validation failures, and optional parsing paths.

**Proposed design (summary):** keep the data plane default as opaque preserve; add a lightweight parser that can extract configured TLV types for logging/mapping, with strict bounds checks and no mutation.

**Alternatives considered:**
- Full TLV interpretation and normalization (rejected: unnecessary complexity and risk for MVP).
- Drop all options (rejected: breaks GWLB metadata expectations).

**Risks:**
- Incorrect validation could drop valid traffic. Mitigation: tight bounds but permissive on unknown TLVs, plus tests with real option fixtures.
- Optional parsing adds hot-path work. Mitigation: off by default and minimal parsing when enabled.

**Rollout plan:**
- Ship with opaque preserve as default.
- Gate optional TLV parsing behind config flags and add logs/metrics for validation drops.

**Datapath impact:** This touches the hot path. Expected performance impact is low when parsing is disabled; small additional overhead when enabled for selected TLVs.

## Capabilities

### New Capabilities
- (none)

### Modified Capabilities
- `geneve-tun-datapath`: extend option handling to include validation, end-to-end preservation guarantees, and optional TLV parsing for logging/mapping.

## Impact

- Updates GENEVE codec and datapath option handling.
- Adds config to enable/disable TLV parsing and to specify allowed TLV types and size bounds.
- Adds new unit/integration tests and pcap fixtures with options present.
- Documentation updates to clarify default opaque preserve behavior and optional parsing.
