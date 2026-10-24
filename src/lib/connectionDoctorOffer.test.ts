import { describe, expect, it, vi } from 'vitest';
import {
  DOCTOR_OFFER_AFTER_MS,
  doctorOfferDueIn,
  initialDoctorOffer,
  runDoctorOffer,
  stepDoctorOffer,
  type DoctorOfferClock,
  type DoctorOfferState,
} from './connectionDoctorOffer';

function run(steps: [boolean, number][]) {
  let state: DoctorOfferState = initialDoctorOffer;
  return steps.map(([limited, at]) => {
    const { next, offer } = stepDoctorOffer(state, limited, at);
    state = next;
    return offer;
  });
}

describe('stepDoctorOffer', () => {
  it('offers once, after ten unbroken minutes of limited reachability', () => {
    const min = 60_000;
    expect(run([[true, 0], [true, 5 * min], [true, DOCTOR_OFFER_AFTER_MS], [true, 30 * min]])).toEqual([
      false,
      false,
      true,
      false,
    ]);
  });

  it('starts the wait again when reachability recovers in between', () => {
    const min = 60_000;
    expect(run([[true, 0], [true, 9 * min], [false, 9.5 * min], [true, 10 * min], [true, 15 * min]])).toEqual([
      false,
      false,
      false,
      false,
      false,
    ]);
  });

  it('never offers to a computer that stays reachable', () => {
    expect(run([[false, 0], [false, DOCTOR_OFFER_AFTER_MS * 3]])).toEqual([false, false]);
  });
});

describe('doctorOfferDueIn', () => {
  it('says when to step again while limited, so the offer fires without a change', () => {
    const { next } = stepDoctorOffer(initialDoctorOffer, true, 1_000);
    expect(doctorOfferDueIn(next, 1_000)).toBe(DOCTOR_OFFER_AFTER_MS);
    const due = 1_000 + DOCTOR_OFFER_AFTER_MS;
    expect(doctorOfferDueIn(next, due + 5)).toBe(0);
    const fired = stepDoctorOffer(next, true, due);
    expect(fired.offer).toBe(true);
    expect(doctorOfferDueIn(fired.next, due)).toBeNull();
  });

  it('has nothing pending while reachable', () => {
    expect(doctorOfferDueIn(initialDoctorOffer, 0)).toBeNull();
  });
});

/** A clock the test moves by hand, with at most one timer pending. */
function fakeClock(start = 0) {
  let now = start;
  let pending: { run: () => void; ms: number } | null = null;
  const clock: DoctorOfferClock = {
    now: () => now,
    setTimeout: (run, ms) => {
      pending = { run, ms };
      return pending;
    },
    clearTimeout: (timer) => {
      if (timer === pending) pending = null;
    },
  };
  return {
    clock,
    pending: () => pending,
    /** Move the clock by `by` and fire the pending timer. */
    fire(by: number) {
      now += by;
      const timer = pending;
      pending = null;
      timer?.run();
    },
  };
}

describe('runDoctorOffer', () => {
  it('offers once the ten minutes have passed, with no change in reachability', () => {
    const fake = fakeClock();
    const state = { current: initialDoctorOffer };
    const onOffer = vi.fn();
    runDoctorOffer(state, true, onOffer, fake.clock);
    expect(fake.pending()?.ms).toBe(DOCTOR_OFFER_AFTER_MS);
    fake.fire(DOCTOR_OFFER_AFTER_MS);
    expect(onOffer).toHaveBeenCalledOnce();
    expect(fake.pending()).toBeNull();
  });

  it('waits again when the timer fires before the offer is due, instead of dropping it', () => {
    const fake = fakeClock();
    const state = { current: initialDoctorOffer };
    const onOffer = vi.fn();
    runDoctorOffer(state, true, onOffer, fake.clock);
    fake.fire(DOCTOR_OFFER_AFTER_MS - 1_000);
    expect(onOffer).not.toHaveBeenCalled();
    expect(fake.pending()?.ms).toBe(1_000);
    fake.fire(1_000);
    expect(onOffer).toHaveBeenCalledOnce();
  });

  it('keeps the stretch across a re-run with the same reachability, and stops when told', () => {
    const fake = fakeClock();
    const state = { current: initialDoctorOffer };
    const onOffer = vi.fn();
    const stop = runDoctorOffer(state, true, onOffer, fake.clock);
    fake.fire(4 * 60_000);
    stop();
    expect(fake.pending()).toBeNull();
    runDoctorOffer(state, true, onOffer, fake.clock);
    expect(fake.pending()?.ms).toBe(DOCTOR_OFFER_AFTER_MS - 4 * 60_000);
  });

  it('sets no timer while reachable', () => {
    const fake = fakeClock();
    const state = { current: initialDoctorOffer };
    runDoctorOffer(state, false, () => {}, fake.clock);
    expect(fake.pending()).toBeNull();
  });
});
