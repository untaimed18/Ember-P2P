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

/** Send a file from this computer to `emberd` at `url`: what it answered
 *  with, or a rejection with the coded error it refused with. */
export async function uploadFile(url: string, file: File): Promise<unknown> {
  const response = await fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'content-type': 'application/octet-stream', [REQUEST_HEADER]: '1' },
    body: file,
  });
  let reply: { ok?: unknown; error?: unknown } | null = null;
  try {
    reply = await response.json();
  } catch {
    // The status is all there is.
  }
  if (response.ok && reply && 'ok' in reply) return reply.ok;
  throw reply?.error ?? `emberd answered ${response.status}`;
}

/**
 * emberd: what stands in for the desktop app's native file picker. The
 * browser's own opens, and the file chosen is sent to `emberd`; the id it is
 * kept under names it to the command that uses it. `null` when nothing was
 * chosen. Call it from the click itself: a browser opens its picker for
 * nothing else.
 */
export function pickAndUpload(accept?: string): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const input = document.createElement('input');
    input.type = 'file';
    if (accept) input.accept = accept;
    input.hidden = true;
    document.body.appendChild(input);
    input.addEventListener(
      'cancel',
      () => {
        input.remove();
        resolve(null);
      },
      { once: true },
    );
    input.addEventListener(
      'change',
      () => {
        const file = input.files?.[0];
        input.remove();
        if (!file) {
          resolve(null);
          return;
        }
        uploadFile(`/api/upload?name=${encodeURIComponent(file.name)}`, file).then(
          (id) => resolve(typeof id === 'string' ? id : null),
          reject,
        );
      },
      { once: true },
    );
    input.click();
  });
}
