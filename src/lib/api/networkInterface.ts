import { invoke } from '@tauri-apps/api/core';

/** One of this computer's network interfaces, for the picker in Settings. */
export interface NetworkInterface {
  /** What Settings keeps: the adapter's GUID on Windows, which a rename does
   *  not change, and its name elsewhere. */
  id: string;
  name: string;
  description: string;
  addresses: string[];
  /** Up, with an address connections can leave from. */
  connected: boolean;
  vpn: boolean;
}

/** Where this run of Ember's connections may leave from. `waiting`: the
 *  chosen interface is not connected yet, and Ember goes online once it is.
 *  `lost`: it went away after Ember went online. `changed`: it is back at
 *  another address, which takes a restart. Nothing goes out in any of those. */
export type NetworkBindingState = 'any' | 'bound' | 'waiting' | 'lost' | 'changed';

export interface NetworkBinding {
  state: NetworkBindingState;
  /** The interface as it was named when chosen. */
  name: string;
  address: string | null;
}

export async function listNetworkInterfaces(): Promise<NetworkInterface[]> {
  return invoke('list_network_interfaces');
}

export async function getNetworkBinding(): Promise<NetworkBinding> {
  return invoke('get_network_binding');
}
