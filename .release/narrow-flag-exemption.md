---
bump: patch
---
bd-safe I-BF1 guard: keep flag values exempt (id-position only). 0.3.0 inspected `--flag value`/`--flag=value` and refused a bare id there, false-positiving a legitimate `--notes "ai-home-1463"`. Native-id admission + case-insensitive id-position refusal retained.
