# Issue #74 [L9] — Culture-sensitive `StartsWith` in invocation-target prefix check

Branch: `74-ordinal-startswith-invocation-target` (off refreshed `main` @ `b786566`, after fetch+rebase).

## Problem (confirmed still open before fixing)
`VerificationService.IsValidInvocationTarget` tested the prefix with the culture-sensitive
`string.StartsWith(string)` overload, while the surrounding logic — the `==` exact-match, the
following `Substring(capabilityTarget.Length)` index math, and the `StartsWith(char)` suffix checks —
is all ordinal. With an ignorable Unicode code point (e.g. U+00AD SOFT HYPHEN) the culture-sensitive
comparison disagrees on length; when the capability target is ordinally **longer** than the invocation
target it returns `true` and the subsequent `Substring` indexes past the end → `ArgumentOutOfRangeException`.
Both call sites (invocation verify, delegation attenuation) are fail-closed (catch → `false`), and real
targets are ASCII URIs, so impact is **low** — a latent correctness/consistency bug.

Confirmed at fix time: the line had moved (issue cited `:556` @ `core-v2.1.1`) but was byte-identical;
it was the **only** culture-sensitive `StartsWith(string)` in `src/`.

## Fix (minimal)
`src/ZcapLd.Core/Services/VerificationService.cs` — one comparison:
```csharp
if (invocationTarget.StartsWith(capabilityTarget, StringComparison.Ordinal))
```
For all real ASCII URIs ordinal and culture-sensitive agree, so **no legitimate behavior changes**;
only the pathological Unicode path is corrected (and the `ArgumentOutOfRangeException` corner case removed).
Also changed `IsValidInvocationTarget` from `private` → `internal` (repo already has
`InternalsVisibleTo ZcapLd.Core.Tests`) so the prefix logic can be unit-tested directly — the
fail-closed call sites make a black-box test indistinguishable.

## Tasks
- [x] Branch off refreshed `origin/main` (fetch + rebase), re-read target file (line moved 556→1211)
- [x] One-line ordinal fix + explanatory comment
- [x] `IsValidInvocationTarget` `private` → `internal` for direct unit testing
- [x] Regression tests: `VerificationServiceTests.cs` — 8 tests (4 valid-prefix theory, 3 invalid-prefix
      theory, 1 `ArgumentOutOfRangeException` guard `Fact`)
- [x] Build green (solution, 0 errors)
- [x] **Ablation**: reverted to culture-sensitive, rebuilt the TEST project (not just Core), confirmed
      the guard `Fact` FAILS with the exact `ArgumentOutOfRangeException` from the issue; restored fix
- [x] Full suite green (Core 486, AspNetCore 6, 0 failures)
- [x] Review section + lesson

## Verification
- **Empirical probe** (.NET 10 / macOS / en-US / ICU): for U+00AD (and U+200B/U+FEFF/U+200C/U+2060/U+0001),
  `cap.StartsWith(cap + ignorable)` returns culture=`true` / ordinal=`false`, and the culture path's
  `Substring` throws `ArgumentOutOfRangeException`. The divergence is real on this platform.
- **Ablation proves the guard**: with the fix reverted (and the *test project* rebuilt so it links the
  reverted Core — see lesson), the guard `Fact` fails with
  `ArgumentOutOfRangeException: startIndex cannot be larger than length of string` at the `Substring`.
  With the fix, all 8 pass. The 7 non-throwing controls pass on both versions (behavior-locking).
- **No regression**: 486 Core + 6 AspNetCore tests pass.

## Review (2026-06-05)
One-line ordinal fix, exactly as the issue recommended; the only nuance was making the prefix helper
`internal` so the regression test can target it directly (the fail-closed callers swallow the bug into a
bare `false`, so a black-box test can't tell the fix from the bug). The guard test was proven by ablation
— and that ablation initially gave a **false PASS** because I rebuilt only `ZcapLd.Core` and ran the tests
with `--no-build`, so the test project linked the *stale fixed* `ZcapLd.Core.dll` already copied into its
`bin`. Rebuilding the test project (omitting `--no-build`) surfaced the real failure. Captured in lessons.

**Files:** `src/ZcapLd.Core/Services/VerificationService.cs` (ordinal comparison + visibility +
comments), `tests/ZcapLd.Core.Tests/Services/VerificationServiceTests.cs` (+8 tests). No public API,
wire-format, or doc-surface change (internal behavior only) → README/ARCHITECTURE untouched.

**Not done (left to user):** GitHub issue #74 not closed/commented — awaiting review. Branch not
committed/pushed (repo policy: commit only when asked).
