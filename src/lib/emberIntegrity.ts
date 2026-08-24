/**
 * Frontend half of the "this download failed its Ember BLAKE3 pin" verdict.
 *
 * Rust classifies the failure in `is_ember_blake3_mismatch` and reduces it to
 * `TransferFailureCode::EmberContentHashMismatch`
 * (`src-tauri/src/network/ed2k/transfer.rs`), whose code rides the IPC boundary
 * on the transfer row. Deciding the badge is therefore a comparison against
 * that code — the substring test this used to repeat lived here only because
 * nothing structured crossed the boundary to say so.
 *
 * The one literal left is the code itself. `scripts/ember-integrity.test.mjs`
 * pins it against the `transfer_failure_codes!` table, so re-spelling it in
 * Rust fails a test instead of silently removing the red badge documented in
 * docs/ember-dht.md. That test lifts this function's body out of the file and
 * runs it, so keep it pure and closed over nothing — including the literal,
 * which is why it is spelled out rather than imported.
 */
export function isEmberBlake3Mismatch(code: string | null | undefined): boolean {
  return code === 'ember_content_hash_mismatch';
}
