import { invoke } from '@tauri-apps/api/core';
import type {
  EmberDiagnostics,
  EmberDhtContact,
  EmberDhtSearchEntry,
  EmberDhtStoreEntry,
} from '$lib/types';

/**
 * Fetch a snapshot of the Ember mesh diagnostic counters: EPX events,
 * LowID broker outcomes, native-transport ping counters, session
 * count, and the local Noise X25519 public key.
 */
export async function getEmberDiagnostics(): Promise<EmberDiagnostics> {
  return invoke<EmberDiagnostics>('get_ember_diagnostics');
}

/**
 * Snapshot the Ember DHT routing table — the contacts this node has
 * learned from signed PING/PONG traffic.
 */
export async function getEmberDhtContacts(): Promise<EmberDhtContact[]> {
  return invoke<EmberDhtContact[]>('get_ember_dht_contacts');
}

/** Snapshot in-flight Ember DHT iterative searches (slice 16). */
export async function getEmberDhtSearches(): Promise<EmberDhtSearchEntry[]> {
  return invoke<EmberDhtSearchEntry[]>('get_ember_dht_searches');
}

/** Snapshot live Ember DHT store keys (slice 16). */
export async function getEmberDhtStore(): Promise<EmberDhtStoreEntry[]> {
  return invoke<EmberDhtStoreEntry[]>('get_ember_dht_store');
}
