# Historical Windows Qualification

Date: 2026-07-25

Scope: local Windows evidence collected before the v1 protocol and durable
evidence contracts were established. It does not qualify the v1 implementation.
The source revision, exact commands and raw outputs were not retained. The
results below are historical notes rather than reproducible qualification
evidence.

## Host
- Windows 11 Pro 10.0.26200, amd64.
- Intel Core i5-13400F, 10 cores and 16 logical processors.
- NTFS evidence volume.
- Go 1.26.5.
- Rust 1.97.1.

## Measurements

Measurement | Result
--- | ---
URL transformation | 426.7 ns/op, 144 B/op, 4 allocations
Protocol response validation | 28.867 µs/op, 11,560 B/op, 300 allocations
Complete operation | 232.297 ms/op, 128,649 B/op, 911 allocations

The complete-operation result used five iterations and includes admission,
AppContainer setup, worker staging and execution, verification, durable
publication and cleanup. It is a local baseline rather than a portability or
service-level guarantee.

## Recorded Results
- Uncached Go tests were recorded as passing.
- Repository-wide Go race tests were recorded as passing.
- Rust tests and Clippy with warnings denied were recorded as passing.
- The package coverage policy was recorded as passing at its declared floors.
- Hostile containment, process, protocol, semantic and evidence cases were
  recorded as passing.

The complete repository gate and final diff review remain separate evidence.
