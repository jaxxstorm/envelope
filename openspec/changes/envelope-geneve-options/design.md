## Context

Envelope currently preserves GENEVE options as opaque bytes and uses them on return traffic. GWLB deployments depend on options for control-plane metadata, and operators need confidence that options are preserved end-to-end and validated for size/bounds. We also want an optional, minimal TLV parser for selected option types to support logging or flow-mapping hints without altering datapath behavior.

## Goals / Non-Goals

**Goals:**
- Preserve GENEVE options end-to-end by default (opaque passthrough).
- Validate option length and size bounds to reject malformed/oversized option blocks.
- Allow optional parsing of selected TLV types for logging/mapping hints, gated by config.
- Keep hot-path overhead minimal when parsing is disabled.

**Non-Goals:**
- Full TLV interpretation or normalization for all options.
- Mutation of options bytes on ingress or egress.
- Adding new external dependencies for parsing.

## Decisions

- **Opaque preserve by default**: options are carried verbatim; parsing is optional and read-only. Alternative: always parse and normalize. Chosen to minimize risk and hot-path cost.
- **Strict bounds checks**: reject options with invalid lengths, non-4-byte alignment, or exceeding max size. Alternative: pass through malformed options. Chosen to prevent unsafe behavior and ambiguity.
- **Config-gated TLV parsing**: only parse specific TLV types when enabled. Alternative: parse all TLVs unconditionally. Chosen to keep cost low and behavior explicit.
- **No allocation-heavy parsing**: parse using existing buffers and avoid copying unless required for logging. Alternative: build structured objects per packet. Chosen to keep GC pressure low.

## Risks / Trade-offs

- [False drops on strict validation] → Mitigation: conform to spec limits, add tests and fixtures, and document bounds.
- [Parsing overhead when enabled] → Mitigation: parse only selected TLVs and avoid allocations.
- [Operator confusion about defaults] → Mitigation: clear docs: opaque preserve is default, parsing is opt-in.

## Migration Plan

- Default behavior remains opaque preserve.
- Introduce config flags for validation bounds and optional TLV parsing.
- Rollback by disabling parsing flags; no data migration required.

## Open Questions

- Which specific TLV types should be supported first for logging/mapping hints?
- Should invalid TLVs be dropped entirely or logged and ignored when parsing is enabled?
