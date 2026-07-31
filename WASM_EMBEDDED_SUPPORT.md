# WASM and Embedded Support

This fork preserves SwiftASN1's parser, serializer, collection, error, and value-ownership contracts while making
the same products usable on ordinary WASM and Embedded WASM.

## Fixed baseline

| Component | Identifier |
|---|---|
| Swift toolchain | `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a` |
| Toolchain identifier | `org.swift.64202607231a` |
| Swift compiler commit | `ef761e567dc94ee` |
| WASM SDK | `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm` |
| Embedded WASM SDK | `swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded` |
| Target | `wasm32-unknown-wasip1` |

## Preserved design contracts

| Concern | Upstream invariant | Fork decision |
|---|---|---|
| Public API | DER and BER parsing expose the same concrete values and lazy element sequence | Preserve parser signatures and element order; Embedded ASN.1 string literals use `StaticString` as their literal associated type while explicit `String` initializers remain available |
| Error contract | Malformed input throws `ASN1Error` or `ASN1MetaError` | Preserve typed failures; do not substitute empty values |
| Ownership | Parsed nodes and byte collections retain value ownership | Keep scoped iterators and owned output arrays |
| Performance | Parsers traverse input once and avoid unnecessary intermediate arrays | Replace unsupported lazy/generic adapters with direct iterators, not copied node graphs |
| Equality and hashing | Object identifiers compare and hash their encoded bytes | Traverse the existing byte slices by index so equality does not materialize arrays or enter the broken WASI `ArraySlice` equality path |
| Platform capability | Foundation supplies Base64 where available | Use the internal Base64 backend only when neither Foundation module exists |
| Compatibility | Native Foundation behavior remains unchanged | Capability-gate the portable backend and retain Native code paths |

The direct iterator implementation consumes the same `ASN1NodeCollection` and invokes the same parser exactly once
per node. Integer serialization appends bytes directly into the serializer-owned output while preserving minimal
signed and unsigned encodings. The portable PEM backend is confined to targets without Foundation and reports
malformed or empty input through the existing error contract.

## Validation

```bash
TOOLCHAINS=org.swift.64202607231a swift run \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm \
  swift-asn1-wasm-validation

TOOLCHAINS=org.swift.64202607231a swift run \
  --swift-sdk swift-6.4.x-DEVELOPMENT-SNAPSHOT-2026-07-23-a_wasm-embedded \
  -Xlinker /path/to/the/matching/libswiftUnicodeDataTables.a \
  -Xlinker -lc++abi \
  swift-asn1-wasm-validation
```

Both target executables validate minimal signed and unsigned DER integer
serialization, integer round trips, DER and BER `SEQUENCE OF`, lazy DER `SET OF`,
object-identifier equality across differently based slices, PEM round trips, and
malformed-input failure. The Embedded executable requires the Unicode data
archive from the exact matching SDK.

The same production validation executable also passed natively. A focused
`xcodebuild test` run executed the object-identifier equality and hash contract
test successfully. Two earlier `xcodebuild test` attempts compiled the selected
integer, set, and PEM tests but were interrupted before executing those tests:
one runner reported an external interrupt and a fresh DerivedData run ended
with `SIGKILL`. Those earlier XCTest selections remain recorded as not executed.

## Native performance

Commit `07df58b` was compared with its parent `5942b1c` using the existing WebPKI PEM benchmarks. Five alternating
release runs were collected per side. Wall-clock results are the medians of the five run medians.

| Path | Base | Candidate | Delta | Base malloc | Candidate malloc |
|---|---:|---:|---:|---:|---:|
| Individual PEM documents | 588,799 ns | 579,583 ns | -1.6% | 549 | 549 |
| Multi-PEM document | 587,775 ns | 575,999 ns | -2.0% | 556 | 556 |

Malloc measurements were run one benchmark at a time because the benchmark package's interposer aborts when both
jobs are run sequentially in one process. Each isolated job completed with more than 1,600 samples and a constant
allocation count. The candidate therefore preserves Native allocation behavior and does not regress either parser
benchmark.
