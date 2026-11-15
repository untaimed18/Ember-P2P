import { REQUEST_HEADER } from './session';

/** Have the browser save what `url` answers with. */
export function saveFrom(url: string): void {
  const link = document.createElement('a');
  link.href = url;
  link.download = '';
  link.rel = 'noopener';
  document.body.appendChild(link);
  link.click();
  link.remove();
}

/**
 * emberd: save a Library file (a finished download is one) to the computer
 * this browser runs on. Asked about first, so a file that is gone says so
 * here instead of as a failed download in the browser's list.
 */
export async function saveToThisComputer(path: string): Promise<void> {
  const url = `/api/file/${encodeURIComponent(path)}`;
  const check = await fetch(url, { method: 'HEAD', credentials: 'same-origin', cache: 'no-store' });
  if (!check.ok) {
    throw JSON.stringify({
      __coded: true,
      code: 'server_file_unavailable',
      message: 'That file is not in the Library',
    });
  }
  saveFrom(url);
}

/** Send a file from this computer to `emberd` at `url`; rejects with the
 *  coded error it answers with. */
export async function uploadFile(url: string, file: File): Promise<void> {
  const response = await fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/octet-stream', [REQUEST_HEADER]: '1' },
    body: file,
  });
  if (response.ok) return;
  let error: unknown = `emberd answered ${response.status}`;
  try {
    const reply = await response.json();
    if (reply && 'error' in reply) error = reply.error;
  } catch {
    // The status is all there is.
  }
  throw error;
}
