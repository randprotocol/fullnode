//! Transient storage (EIP-1153, Cancun): the key→value map `TLOAD`/`TSTORE` read and write.
//!
//! It is a separate map from the contract storage tree ([`crate::storage`]) and has none of its
//! machinery: no witness, no Merkle path, no root. It starts empty at the start of every call
//! ([`crate::interp::Interpreter::new`] makes a fresh one) and is dropped at its end, so nothing
//! in it is ever persisted, bound by the public output or written to the storage tree. `TLOAD` of
//! a key never stored reads zero.
//!
//! **A fixed table**, like every other working array of the interpreter: at most
//! [`MAX_TRANSIENT_SLOTS`] distinct keys, searched linearly. [`Transient::store`] of a key the
//! table already holds overwrites it (zero included); of a new key with a zero value it is a
//! no-op — that key reads zero whether or not it has an entry — and of a new key with a non-zero
//! value it takes the next entry, or fails with [`Full`] when there is none, which the
//! interpreter turns into the capacity halt (`Halt::OutOfBounds`). The C runtime a translated
//! contract runs on (`evm-rt/evm_cancun.c`) implements exactly these rules with the same bound.

use crate::interp::MAX_TRANSIENT_SLOTS;
use crate::u256::U256;

/// [`Transient::store`] needed a new entry and the table was full.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Full;

/// One call's transient storage.
#[derive(Clone, Copy)]
pub struct Transient {
    keys: [U256; MAX_TRANSIENT_SLOTS],
    values: [U256; MAX_TRANSIENT_SLOTS],
    n: usize,
}

impl Transient {
    /// The empty map: what every call starts with.
    pub const EMPTY: Transient = Transient {
        keys: [U256::ZERO; MAX_TRANSIENT_SLOTS],
        values: [U256::ZERO; MAX_TRANSIENT_SLOTS],
        n: 0,
    };

    fn find(&self, key: &U256) -> Option<usize> {
        (0..self.n).find(|&i| self.keys[i] == *key)
    }

    /// `TLOAD`: the value stored under `key`, zero if none.
    pub fn load(&self, key: &U256) -> U256 {
        match self.find(key) {
            Some(i) => self.values[i],
            None => U256::ZERO,
        }
    }

    /// `TSTORE`: see the module docs for the table's rules.
    pub fn store(&mut self, key: &U256, value: U256) -> Result<(), Full> {
        if let Some(i) = self.find(key) {
            self.values[i] = value;
            return Ok(());
        }
        if value.is_zero() {
            return Ok(());
        }
        if self.n == MAX_TRANSIENT_SLOTS {
            return Err(Full);
        }
        self.keys[self.n] = *key;
        self.values[self.n] = value;
        self.n += 1;
        Ok(())
    }

    /// How many entries the table holds.
    pub fn len(&self) -> usize {
        self.n
    }

    pub fn is_empty(&self) -> bool {
        self.n == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_map_reads_zero_and_the_last_store_wins() {
        let mut t = Transient::EMPTY;
        assert_eq!(t.load(&U256::ONE), U256::ZERO);
        t.store(&U256::ONE, U256::from_u32(7)).unwrap();
        t.store(&U256::from_u32(2), U256::from_u32(8)).unwrap();
        t.store(&U256::ONE, U256::from_u32(9)).unwrap();
        assert_eq!(t.load(&U256::ONE), U256::from_u32(9));
        assert_eq!(t.load(&U256::from_u32(2)), U256::from_u32(8));
        assert_eq!(t.len(), 2);
        t.store(&U256::ONE, U256::ZERO).unwrap();
        assert_eq!(t.load(&U256::ONE), U256::ZERO);
        assert_eq!(t.len(), 2, "a zero over an entry keeps the entry");
    }

    #[test]
    fn the_table_is_bounded_and_a_zero_store_to_a_new_key_takes_no_entry() {
        let mut t = Transient::EMPTY;
        for k in 0..MAX_TRANSIENT_SLOTS as u32 {
            t.store(&U256::from_u32(k), U256::ONE).unwrap();
        }
        assert_eq!(t.store(&U256::MAX, U256::ONE), Err(Full));
        assert_eq!(t.store(&U256::MAX, U256::ZERO), Ok(()));
        assert_eq!(t.store(&U256::ZERO, U256::from_u32(5)), Ok(()));
        assert_eq!(t.load(&U256::ZERO), U256::from_u32(5));
        assert_eq!(t.load(&U256::MAX), U256::ZERO);
        assert_eq!(t.len(), MAX_TRANSIENT_SLOTS);
    }
}
