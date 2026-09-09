//! SHRUGG chain core: cryptography, types, ledger, and HotStuff consensus.
//! Pure logic with no I/O so it can be tested deterministically.

pub mod confidential;
pub mod consensus;
pub mod crypto;
pub mod effect;
pub mod gas;
pub mod genesis;
pub mod ledger;
pub mod program;
pub mod types;

pub use crypto::{Address, Hash, Keypair, PublicKey, Signature};
pub use ledger::{Account, BlockError, Ledger, TxError};
pub use program::{CallOutcome, CallReceipt, ProgramId, ProgramRecord};
pub use types::*;
