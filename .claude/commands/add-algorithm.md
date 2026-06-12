# /add-algorithm

Scaffold support for a new COSE algorithm in passforge (e.g. RS256, EdDSA).

## Steps

1. **Identify the algorithm** — ask the user which COSE algorithm to add if not specified (common choices: RS256 = -257, EdDSA = -8).

2. **Add the enum variant** in `src/credential.rs`:
   - Add a new `PublicKey` variant, e.g. `EdDSA(Vec<u8>)`, with a `///` doc comment describing the key format.

3. **Add the COSE algorithm constant** in `src/crypto.rs`:
   - Define a named constant for the COSE algorithm identifier integer (e.g. `pub const COSE_ALG_EDDSA: i64 = -8;`).

4. **Add the verification function** in `src/crypto.rs`:
   - Implement a `verify_<alg>_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool` using `ring`.
   - Document the key format expected and any spec references.

5. **Wire in the authentication path** in `src/authentication.rs`:
   - Add a match arm in the `PublicKey` match expression inside `verify` to call the new verification function.
   - Add the spec step comment citing the relevant RFC/COSE spec section.

6. **Update COSE key parsing** in `src/authenticator_data.rs`:
   - Make sure the new algorithm's COSE key fields (kty, crv, x, y or n, e) are parsed correctly in `parse_cose_key`.

7. **Write unit tests** — add a `#[test]` in `src/crypto.rs` that:
   - Generates a real keypair using `ring`.
   - Signs a known message.
   - Verifies the signature with the new function → assert true.
   - Corrupts a byte and verifies → assert false.

8. **Write an integration test** — add a test to `tests/integration.rs` following the `Fixture` pattern that exercises a full registration + authentication round-trip with the new key type.

9. **Remind yourself**: update `docs/architecture.md` to reflect the new algorithm support, and remove the entry from "Known limitations" in `CLAUDE.md` if the algorithm was previously listed there.
