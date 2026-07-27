# Windows Qualification v1

Date: 2026-07-25

Scope: local Windows evidence for the internal governed URL-reference
operation.

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

## Evidence
- Uncached Go tests pass.
- Repository-wide Go race tests pass.
- Rust tests and Clippy with warnings denied pass.
- The package coverage policy passes at its declared floors.
- Hostile containment, process, protocol, semantic and evidence cases pass.

The complete repository gate and final diff review remain separate evidence.
