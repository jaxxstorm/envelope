## Context

Envelope's raw option copy is the correct baseline for GWLB, but correctness also depends on validating the option structure and honoring critical bits. The current parser treats all eight bits of the option length byte as length, allocates a descriptor slice for every option, and uses non-AWS fixtures. AWS GWLB class `0x0108` commonly carries VPCE identity and a flow cookie that must return unchanged.

## Goals / Non-Goals

**Goals:**
- Preserve the complete ordered options block associated with a flow without mutation or reordering.
- Validate TLV structure according to RFC 8926, including reserved and critical bits.
- Recognize AWS option shapes for validation and safe observability.
- Keep value parsing opt-in and keep mandatory structural validation allocation-free.
- Establish fixtures that represent actual AWS GWLB metadata.

**Non-Goals:**
- Using parsed options to choose a route or return mapping.
- Reconstructing, sorting, normalizing, inserting, or deleting options.
- Supporting every current or future AWS option type.
- Adding external parsing dependencies.

## Decisions

### 1. Raw ordered bytes remain authoritative

The datapath stores one copy of the complete options slice in the matching flow context. Parsed values are views used for validation and optional logging only. Return traffic emits the stored slice, not a re-encoded representation.

Alternative: decode and re-encode known options. Rejected because unknown options and ordering are part of GWLB's return contract.

### 2. Structural validation always scans headers

Every option header is scanned to verify bounds and total length. Option data length is `(lengthByte & 0x1f) * 4`; the upper three reserved bits are ignored on receive. The option type's high bit is treated as critical, separately from the seven-bit type value. Validation uses an iterator/callback and does not allocate a result slice when logging is disabled.

Alternative: validate only the base header's aggregate option length. Rejected because malformed internal TLVs and unknown critical options would pass unnoticed.

### 3. Critical options fail closed

If the base critical bit is set, all options are scanned. An unknown critical option causes the packet to be dropped. A critical option without the base critical bit, or the base bit without any critical option, is malformed. Unknown non-critical options remain opaque and pass validation.

### 4. AWS class recognition is narrow and forward-compatible

Class `0x0108` recognizes type 1 VPCE ID with 8 bytes, type 2 attachment ID with 8 bytes when present, and type 3 flow cookie with 4 bytes. The AWS profile requires exactly one flow cookie and permits at most one VPCE ID and one attachment ID. Known types with wrong lengths or invalid multiplicity are rejected. Unknown non-critical AWS types are preserved and accepted. Mandatory flow-cookie extraction for wire identity is independent of the value-logging allowlist.

### 5. Fixtures prove fidelity, not just parsing

Parser fixtures include multiple AWS options, altered ordering, non-zero reserved bits, malformed lengths, missing/duplicate flow cookies, unknown non-critical options, and unknown critical options. Byte-identical return fixtures use standards-valid zero reserved bits because reserved bits must be zero on transmission. Sensitive production payloads and identifiers are sanitized.

## Risks / Trade-offs

- [Mandatory header scanning adds ingress work] -> Use a zero-allocation iterator and benchmark options-disabled and AWS-options paths.
- [Strict critical-bit checks reject unusual peers] -> Scope behavior to standards-compliant GENEVE and add explicit metrics for rejection reasons.
- [Fixture sanitization accidentally changes structure] -> Preserve lengths/order and validate fixtures with an independent packet decoder.

## Migration Plan

1. Add standards-correct iterator and focused unit tests.
2. Add critical-bit and AWS option validation.
3. Replace fixtures and round-trip assertions.
4. Switch ingress validation to the iterator and remove allocation-heavy parser use from the hot path.
5. Keep raw preservation as the rollback-safe default; disabling value logging does not disable structural validation.

## Open Questions

- None. Additional AWS option types require a follow-up specification when their semantics are known.
