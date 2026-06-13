# /check

Run the full WebAuthn quality suite and report results.

## Steps

Run each check sequentially and collect pass/fail status:

1. **Build**
   ```
   cargo build
   ```

2. **Clippy**
   ```
   cargo clippy -- -D warnings
   ```

3. **Tests**
   ```
   cargo test
   ```

4. **Format**
   ```
   cargo fmt --check
   ```

## Output format

After all checks complete, print a summary table:

```
=== WebAuthn quality check ===
✅ cargo build
✅ cargo clippy (zero warnings)
✅ cargo test   (N tests passed)
✅ cargo fmt    (no formatting issues)
================================
All checks passed.
```

Or if any fail:

```
=== WebAuthn quality check ===
✅ cargo build
❌ cargo clippy — N warnings found
✅ cargo test   (N tests passed)
❌ cargo fmt    — run `cargo fmt` to fix
================================
2 checks failed.
```

Fix any failures before reporting the task as done.
