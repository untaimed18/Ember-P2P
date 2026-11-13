//! How long the `*_fuzz_never_panics` loops run, and from where.
//!
//! Every push runs each loop as written, from its own fixed seed, so a failure
//! there is the same failure everywhere. The nightly soak
//! (`.github/workflows/soak.yml`) sets `EMBER_FUZZ_SCALE` to run each many
//! times longer and `EMBER_FUZZ_SEED` to start somewhere new each night; the
//! seed a loop used is printed, so a failure it finds can be run again.

/// `base` rounds, times `EMBER_FUZZ_SCALE` when it is set.
pub(crate) fn rounds(base: usize) -> usize {
    let scale = std::env::var("EMBER_FUZZ_SCALE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&scale| scale > 0)
        .unwrap_or(1);
    base.saturating_mul(scale)
}

/// The loop's generator: from `seed`, or from `seed` mixed with
/// `EMBER_FUZZ_SEED` when that is set.
pub(crate) fn rng(seed: u64) -> rand::rngs::StdRng {
    let seed = match std::env::var("EMBER_FUZZ_SEED").ok().and_then(|value| value.parse::<u64>().ok()) {
        Some(mix) => {
            let seed = seed ^ mix;
            eprintln!("fuzz seed {seed:#018x} (EMBER_FUZZ_SEED={mix})");
            seed
        }
        None => seed,
    };
    rand::SeedableRng::seed_from_u64(seed)
}
