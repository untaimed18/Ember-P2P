import * as m from '$lib/paraglide/messages';

/**
 * Open the web address `address` resolves to in a new tab. The tab opens
 * first, while the click that asked is still being handled: a browser blocks a
 * tab opened once that is over, and the address has to come from `emberd`.
 */
export async function openInNewTab(address: Promise<string>): Promise<void> {
  const tab = window.open('', '_blank');
  if (tab) tab.opener = null;
  let url: string;
  try {
    url = await address;
  } catch (error) {
    tab?.close();
    throw error;
  }
  if (!/^https?:\/\//i.test(url)) {
    tab?.close();
    throw new Error(m.web_runtime_not_web_address());
  }
  if (tab) tab.location.replace(url);
  else window.open(url, '_blank', 'noopener,noreferrer');
}
