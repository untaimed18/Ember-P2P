import { describe, expect, it } from 'vitest';
import {
  DOCTOR_OFFER_AFTER_MS,
  doctorOfferDueIn,
  initialDoctorOffer,
  stepDoctorOffer,
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
