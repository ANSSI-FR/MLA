use rand::SeedableRng as _;
use rand_chacha::ChaCha20Rng;

use crate::layers::encrypt::get_crypto_rng;

pub(crate) mod aesgcm;
pub(crate) mod hash;
pub(crate) mod hpke;
pub(crate) mod hybrid;
pub(crate) mod hybrid_signature;
pub mod mlakey;

pub(crate) enum MaybeSeededRNG {
    System,
    #[allow(dead_code)]
    Seed([u8; 32]),
}

impl MaybeSeededRNG {
    pub(crate) fn get_rng(&self) -> ChaCha20Rng {
        match self {
            MaybeSeededRNG::System => get_crypto_rng(),
            MaybeSeededRNG::Seed(s) => ChaCha20Rng::from_seed(*s),
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for MaybeSeededRNG {
    fn default() -> Self {
        MaybeSeededRNG::System
    }
}
