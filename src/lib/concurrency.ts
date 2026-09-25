/**
 * `Promise.allSettled` over `items`, with at most `limit` calls of `fn` in
 * flight at once. Results keep the order of `items`. A synchronous throw from
 * `fn` is reported as a rejection for that item rather than aborting the run.
 */
export async function mapSettledWithLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<PromiseSettledResult<R>[]> {
  const results: PromiseSettledResult<R>[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next++;
      try {
        results[index] = { status: 'fulfilled', value: await fn(items[index], index) };
      } catch (reason) {
        results[index] = { status: 'rejected', reason };
      }
    }
  };
  const width = Math.max(1, Math.min(Math.floor(limit) || 1, items.length));
  await Promise.all(Array.from({ length: items.length === 0 ? 0 : width }, worker));
  return results;
}
