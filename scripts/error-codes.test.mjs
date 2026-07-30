import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rustRoot = join(root, "src-tauri", "src");
const messagesDir = process.env.EMBER_MESSAGES_DIR ?? join(root, "messages");

/**
 * Error codes the Rust side can emit that have no `error_*` translation yet.
 *
 * The frontend falls back to the English message embedded in the coded error
 * envelope, so a missing key shows English rather than breaking — which is
 * exactly why the backlog below accumulated unnoticed, and why four new ones
 * slipped in during a single release cycle before this check existed.
 *
 * Treat it as a ratchet, not a licence: adding a code means adding its key, and
 * the test below fails if an entry here becomes stale, so the list can only
 * shrink.
 */
const KNOWN_UNTRANSLATED = new Set([
  // `coded("test", ...)` inside the error-envelope unit tests.
  "test",
  "collections_author_too_long",
  "collections_canonicalize_task",
  "collections_dialog_task_failed",
  "collections_empty_file_name",
  "collections_file_name_too_long",
  "collections_file_too_large",
  "collections_invalid_aich_hash",
  "collections_invalid_file_hash",
  "collections_invalid_path",
  "collections_name_too_long",
  "collections_path_too_long",
  "collections_stat_failed",
  "deeplink_queue_save_failed",
  "deeplink_queue_serialize_failed",
  "gzip_decompressed_too_large",
  "peers_bootstrap_timeout",
  "peers_cannot_ping_private",
  "peers_friend_removal_not_acknowledged",
  "peers_invalid_browse_request",
  "preview_request_in_flight",
  "search_ed2k_link_batch_too_large",
  "search_ed2k_link_too_long",
  "search_file_extension_too_long",
  "search_file_type_too_long",
  "search_history_clear_failed",
  "search_history_fetch_failed",
  "search_history_remove_failed",
  "search_history_stats_failed",
  "search_invalid_file_type",
  "search_link_sources_timeout",
  "search_note_file_name_too_long",
  "search_note_publish_failed",
  "search_note_publish_unavailable",
  "search_notes_busy",
  "search_source_search_busy",
  "search_spam_invalid_server_ip",
  "security_policy_reset_failed",
  "security_policy_reset_task_failed",
  "server_name_too_long",
  "settings_cannot_share_data_dir",
  "settings_download_folder_root",
  "settings_extraction_task_failed",
  "settings_folder_priority_path_too_long",
  "settings_invalid_update",
  "settings_max_download_speed_invalid",
  "settings_max_upload_speed_invalid",
  "settings_shared_folder_root",
  "settings_too_many_folder_priorities",
  "settings_transaction_task_failed",
  "settings_update_check_frequency_invalid",
  "sharing_batch_bytes_too_large",
  "sharing_cannot_share_data_dir",
  "sharing_cannot_share_root",
  "sharing_config_transaction_error",
  "sharing_file_hash_pending",
  "sharing_invalid_picker_path",
  "sharing_media_request_in_flight",
  "sharing_not_a_file",
  "sharing_persist_priority_failed",
  "sharing_persist_state_failed",
  "sharing_picker_task_failed",
  "sharing_picker_wrong_window",
  "sharing_priority_rollback_failed",
  "sharing_reconcile_failed",
  "sharing_reload_in_flight",
  "sharing_reveal_unsafe_file_failed",
  "sharing_state_rollback_failed",
  "speed_test_already_running",
  "transfers_batch_bytes_too_large",
  "transfers_category_persist_failed",
  "transfers_category_task_failed",
  "transfers_existing_download_aich_mismatch",
  "transfers_file_size_exceeds_max",
  "transfers_invalid_transfer_id",
  "transfers_overflow_notice_failed",
  "transfers_overflow_notice_task_failed",
  "transfers_part_path_invalid",
  "transfers_part_verify_failed",
  "transfers_pending_budget_exceeded",
  "transfers_priority_persist_failed",
  "transfers_priority_task_failed",
  "transfers_recovery_timed_out",
  "transfers_recovery_unavailable",
  "transfers_reveal_unsafe_file_failed",
  "transfers_temp_path_invalid",
  "transfers_temp_path_reparse",
]);

/** Every construction site that turns a code into an error the UI localises. */
const CODE_PATTERNS = [
  /coded(?:_ctx)?\(\s*"([a-z0-9_]+)"/gs,
  /await_reply\(\s*[A-Za-z0-9_]+\s*,\s*"([a-z0-9_]+)"/gs,
];

function rustFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) out.push(...rustFiles(path));
    else if (entry.endsWith(".rs")) out.push(path);
  }
  return out;
}

function emittedCodes() {
  const codes = new Map();
  for (const file of rustFiles(rustRoot)) {
    const source = readFileSync(file, "utf8");
    for (const pattern of CODE_PATTERNS) {
      for (const match of source.matchAll(pattern)) {
        if (!codes.has(match[1])) codes.set(match[1], file);
      }
    }
  }
  return codes;
}

const codes = emittedCodes();
const englishKeys = new Set(
  Object.keys(JSON.parse(readFileSync(join(messagesDir, "en.json"), "utf8"))),
);

test("every error code the backend emits is translated", () => {
  const untranslated = [...codes.keys()].filter(
    (code) => !englishKeys.has(`error_${code}`) && !KNOWN_UNTRANSLATED.has(code),
  );
  assert.deepEqual(
    untranslated.map((code) => `${code} (${codes.get(code)})`),
    [],
    "add error_<code> to messages/en.json and the five translations",
  );
});

test("the untranslated backlog has no stale entries", () => {
  // An entry that has since been translated, or whose code no longer exists,
  // must come off the list — otherwise it silently re-permits a future
  // regression under the same name.
  const translated = [...KNOWN_UNTRANSLATED].filter((code) =>
    englishKeys.has(`error_${code}`),
  );
  assert.deepEqual(
    translated,
    [],
    "these are translated now; remove them from KNOWN_UNTRANSLATED",
  );

  const gone = [...KNOWN_UNTRANSLATED].filter((code) => !codes.has(code));
  assert.deepEqual(
    gone,
    [],
    "these codes are no longer emitted; remove them from KNOWN_UNTRANSLATED",
  );
});

test("a sane number of codes was actually discovered", () => {
  // Guards the scan itself: a broken pattern or path would make both checks
  // above pass by finding nothing at all.
  assert.ok(
    codes.size > 200,
    `expected to find many error codes, found ${codes.size}`,
  );
});
