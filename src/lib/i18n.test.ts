import { describe, expect, it } from 'vitest';
import { codedErrorOf, translateError } from './i18n';

/** The envelope `commands::errors` puts on the wire. */
function coded(code: string, message: string, context?: string): string {
  return JSON.stringify({ __coded: true, code, message, ...(context ? { context } : {}) });
}

describe('codedErrorOf', () => {
  it('exposes the code and context a caller has to act on', () => {
    // The slow-mode countdown reads the remaining seconds out of `context`,
    // which `translateError` folds into a sentence and never hands back.
    expect(codedErrorOf(coded('channels_slow_mode', 'Slow mode is on', '12'))).toEqual({
      code: 'channels_slow_mode',
      context: '12',
    });
  });

  it('returns null for anything that is not one of our envelopes', () => {
    expect(codedErrorOf('plain failure text')).toBeNull();
    expect(codedErrorOf('{"not":"ours"}')).toBeNull();
    // Valid JSON, right shape, missing the sentinel.
    expect(codedErrorOf('{"code":"x","message":"y"}')).toBeNull();
    expect(codedErrorOf('')).toBeNull();
    expect(codedErrorOf(null)).toBeNull();
    expect(codedErrorOf(undefined)).toBeNull();
    expect(codedErrorOf({ code: 'x' })).toBeNull();
  });

  it('reads an envelope carried on an Error', () => {
    const err = new Error(coded('channels_banned', 'You are banned'));
    expect(codedErrorOf(err)?.code).toBe('channels_banned');
  });
});

describe('translateError', () => {
  it('translates a code the catalog knows', () => {
    const text = translateError(coded('settings_open_link_invalid', 'English fallback'));
    expect(text).toBe('That link cannot be opened safely');
  });

  it('interpolates the context into a message that asks for it', () => {
    const text = translateError(coded('settings_open_link_failed', 'English fallback', 'boom'));
    expect(text).toContain('boom');
  });

  it('falls back to the embedded English for a code the catalog has no key for', () => {
    // A newer backend against an older UI must not produce a blank error.
    const text = translateError(coded('a_code_that_will_never_exist', 'Something went wrong'));
    expect(text).toBe('Something went wrong');
  });

  it('appends the context to an unknown code rather than dropping it', () => {
    const text = translateError(
      coded('another_code_that_will_never_exist', 'Something went wrong', 'detail here'),
    );
    expect(text).toBe('Something went wrong: detail here');
  });

  it('shows a foreign error string verbatim', () => {
    expect(translateError('some underlying failure')).toBe('some underlying failure');
  });

  it('uses the caller fallback only when there is no string at all', () => {
    expect(translateError(null, 'could not send')).toBe('could not send');
    expect(translateError('real text', 'could not send')).toBe('real text');
  });
});
