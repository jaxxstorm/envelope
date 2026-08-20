## Why

AWS GWLB uses ordered GENEVE options, including a flow cookie, to validate return traffic. Envelope preserves raw bytes in simple tests, but its optional parser does not follow the five-bit option-length field, critical-option semantics are undefined, and its fixtures are not representative of AWS class `0x0108`.

## What Changes

- Preserve the complete ordered options block byte-for-byte for the matching flow, including unknown non-critical options.
- Validate every TLV header using the low five length bits while ignoring reserved bits on receive.
- Implement GENEVE base critical-bit and option critical-bit behavior, including fail-closed handling for unknown critical options.
- Add read-only recognition and length validation for AWS class `0x0108` VPCE ID, attachment ID, and flow cookie options without normalizing their bytes.
- Parse or log only configured option values while performing allocation-free structural validation for the complete block.
- Replace synthetic-only coverage with sanitized AWS captures or wire-identical fixtures containing multiple options, ordering variations, reserved bits, and malformed cases.
- Remove unspecified "mapping hint" behavior; option parsing is for validation and observability only in this change.

## Capabilities

### New Capabilities
- (none)

### Modified Capabilities
- `geneve-tun-datapath`: make ordered option preservation, TLV bounds, critical-option handling, AWS option validation, and fixture acceptance precise.

## Impact

- Affects the GENEVE codec/parser, datapath validation, configuration, metrics, fixtures, and documentation.
- Touches ingress hot-path validation; the implementation must scan option headers without allocating per packet when value parsing is disabled.
- Supplies the metadata prerequisite for the subsequent GWLB wire-compliance change.
