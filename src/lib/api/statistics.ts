import { invoke } from '@tauri-apps/api/core';

export interface TransferStats {
  session_downloaded: number;
  session_uploaded: number;
  session_down_overhead: number;
  session_up_overhead: number;
  session_down_rate: number;
  session_up_rate: number;
  session_completed_down: number;
  session_completed_up: number;
  session_start_time: number;
  cum_downloaded: number;
  cum_uploaded: number;
  cum_down_overhead: number;
  cum_up_overhead: number;
  cum_conn_time: number;
  cum_completed_down: number;
  cum_completed_up: number;
  stat_last_reset: number;
  overhead_server: number;
  overhead_kad: number;
  overhead_source_exchange: number;
  overhead_file_request: number;
}

export async function getStatistics(): Promise<TransferStats> {
  return invoke('get_statistics');
}
