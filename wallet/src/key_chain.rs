// Copyright (c) 2023 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! # BIP39 key chain
//! The KeyChain struct holds and constantly derives keys for the wallet addresses
//! It uses the following derivation scheme:
//!
//! m/0'/<account_number>'/<key_purpose>'/<key_index>'
//!
//! Where `account_number` is the index of an account,
//!       `key_purpose` is if the generated address is for receiving or change purposes and this
//!                     value is 0 or 1 respectively,
//!       `key_index` starts from 0 and it is incremented for each new address

use common::address::{Address, AddressError};
use common::chain::config::create_regtest;
use common::chain::{ChainConfig, Destination};
use crypto::key::extended::{ExtendedKeyKind, ExtendedPrivateKey, ExtendedPublicKey};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::{Derivable, DerivationError};
use crypto::key::hdkd::derivation_path::DerivationPath;
use serialization::{Decode, Encode};
use std::collections::BTreeMap;
use std::slice::Iter;
use std::str::FromStr;
use std::sync::Arc;
use storage::Backend;
use wallet_storage::{Store, WalletStorageRead};
use zeroize::Zeroize;

/// Path leading to accounts paths
const ACCOUNTS_PATH: [ChildNumber; 1] = [ChildNumber::ZERO_H];
/// Default account index
const DEFAULT_ACCOUNT_INDEX: ChildNumber = ChildNumber::ZERO_H;
/// Size of individual account key tree: account_number, key_purpose, key_index
const ACCOUNT_KEY_TREE_DEPTH: usize = 3;
/// The maximum derivation path length
const MAX_KEY_TREE_DEPTH: usize = ACCOUNTS_PATH.len() + ACCOUNT_KEY_TREE_DEPTH;
/// Default cryptography type
const KEY_KIND: ExtendedKeyKind = ExtendedKeyKind::Secp256k1Schnorr;
/// Default size of the number of unused addresses that need to be checked after the
/// last used address.
const LOOKAHEAD_SIZE: u16 = 100;

/// KeyChain errors
#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum KeyChainError {
    #[error("Bip39 error: {0}")]
    Bip39(bip39::Error),
    #[error("Key derivation error: {0}")]
    Derivation(#[from] DerivationError),
    #[error("Address error: {0}")]
    Address(#[from] AddressError),
    #[error("Key chain is locked")]
    MissingPrivateKey,
    #[error("No account found: {0}")]
    NoAccountFound(DerivationPath),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum AccountKeyId {
    Derived(AccountHDPath),
}

/// The KeyChainEntry is is used for
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct AccountHDPath([ChildNumber; ACCOUNT_KEY_TREE_DEPTH]);

impl AccountHDPath {
    pub fn new(
        account_number: ChildNumber,
        key_purpose: ChildNumber,
        key_index: ChildNumber,
    ) -> Self {
        AccountHDPath([account_number, key_purpose, key_index])
    }
}

impl TryFrom<ExtendedPublicKey> for AccountHDPath {
    type Error = KeyChainError;

    fn try_from(pk: ExtendedPublicKey) -> KeyChainResult<Self> {
        // let path = pk.get_derivation_path();
        todo!()
    }
}

/// Result type used for the key chain
type KeyChainResult<T> = Result<T, KeyChainError>;

/// The usage purpose of a key i.e. if it is for receiving funds or for change
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum KeyPurpose {
    /// This is for addresses created for receiving funds that are given to the user
    ReceiveFunds = 0,
    /// This is for the internal usage of the wallet when creating change output for a transaction
    Change = 1,
}

impl KeyPurpose {
    const ALL: [KeyPurpose; 2] = [KeyPurpose::ReceiveFunds, KeyPurpose::Change];
}

pub struct MasterKeyChain<B: Backend> {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,

    /// The database connection
    // TODO Consider if this should be an Option
    db: Arc<Store<B>>,

    /// The master key of this key chain from where all the keys are derived from
    // TODO implement encryption
    root_key: ExtendedPrivateKey,

    /// A list of accounts that are derived from the same master key
    // TODO This will be removed as wallet account will hold a AccountKeyChain<B>
    accounts: BTreeMap<ChildNumber, Arc<AccountKeyChain<B>>>,
}

impl<B: Backend> MasterKeyChain<B> {
    pub fn new_from_mnemonic(
        chain_config: Arc<ChainConfig>,
        db: Arc<Store<B>>,
        mnemonic_str: &str,
        passphrase: Option<&str>,
    ) -> KeyChainResult<Self> {
        let mut mnemonic = bip39::Mnemonic::parse(mnemonic_str).map_err(KeyChainError::Bip39)?;
        let mut seed = mnemonic.to_seed(passphrase.unwrap_or(""));
        let root_key = ExtendedPrivateKey::new_master(&seed, KEY_KIND)?;
        mnemonic.zeroize();
        seed.zeroize();

        let default_account = Arc::new(AccountKeyChain::new_from_root_key(
            chain_config.clone(),
            db.clone(),
            &root_key,
            DEFAULT_ACCOUNT_INDEX,
        )?);

        let accounts = BTreeMap::from([(DEFAULT_ACCOUNT_INDEX, default_account)]);

        Ok(MasterKeyChain {
            chain_config,
            root_key,
            db,
            accounts,
        })
    }

    /// Load the Master key chain from database and all the account key chains it derives
    pub fn load_from_database(
        chain_config: Arc<ChainConfig>,
        db: Arc<Store<B>>,
    ) -> KeyChainResult<Self> {
        // TODO remove this
        let _ = db.get_storage_version().expect("This should work?");

        let master_key = ExtendedPrivateKey::new_from_entropy(KEY_KIND).0;

        // TODO load accounts
        let default_account = Arc::new(AccountKeyChain::new_from_root_key(
            chain_config.clone(),
            db.clone(),
            &master_key,
            DEFAULT_ACCOUNT_INDEX,
        )?);

        let accounts = BTreeMap::from([(DEFAULT_ACCOUNT_INDEX, default_account)]);

        // TODO implement loading from database
        Ok(MasterKeyChain {
            chain_config,
            root_key: master_key,
            db,
            accounts,
        })
    }

    pub fn create_account_key_chain(
        new_index: ChildNumber,
    ) -> KeyChainResult<Arc<AccountKeyChain<B>>> {
        Err(KeyChainError::MissingPrivateKey)
    }

    pub(crate) fn get_default_account_key_chain(&mut self) -> KeyChainResult<&AccountKeyChain<B>> {
        Ok(self
            .accounts
            .get(&DEFAULT_ACCOUNT_INDEX)
            .ok_or_else(|| KeyChainError::NoAccountFound(account_path(DEFAULT_ACCOUNT_INDEX)))?)
    }
}

#[allow(dead_code)] // TODO remove
/// This key chain contains a pool of pre-generated keys and addresses for the usage in a wallet
pub struct AccountKeyChain<B: Backend> {
    /// The specific chain this KeyChain is based on, this will affect the address format
    chain_config: Arc<ChainConfig>,

    /// The database connection
    // TODO Consider if this should be an Option
    db: Arc<Store<B>>,

    /// The account key from which all the addresses are derived
    account_pubkey: ExtendedPublicKey,

    account_privkey: Option<ExtendedPrivateKey>,

    /// The derived destinations/addresses for each `KeyPurpose`. Those are derived as needed.
    destinations: [BTreeMap<ChildNumber, Destination>; 2],

    /// Last used destination index per `KeyPurpose`. A destination might not be used so the
    /// corresponding entry would be None, otherwise it would be that last used ChildNumber
    last_used: [Option<ChildNumber>; 2],

    /// Last issued destination to the user
    last_issued: [Option<ChildNumber>; 2],

    /// The number of unused addresses that need to be checked after the last used address
    lookahead_size: u16,
}

#[allow(dead_code)] // TODO remove
impl<B: Backend> AccountKeyChain<B> {
    fn new_from_root_key(
        chain_config: Arc<ChainConfig>,
        db: Arc<Store<B>>,
        root_key: &ExtendedPrivateKey,
        num: ChildNumber,
    ) -> KeyChainResult<AccountKeyChain<B>> {
        let account_path = account_path(num);

        let account_privkey = root_key.clone().derive_path(&account_path)?;

        let mut new_account = AccountKeyChain {
            chain_config,
            db,
            account_pubkey: ExtendedPublicKey::from_private_key(&account_privkey),
            account_privkey: Some(account_privkey),
            destinations: KeyPurpose::ALL.map(|_| BTreeMap::new()),
            last_used: KeyPurpose::ALL.map(|_| None),
            last_issued: KeyPurpose::ALL.map(|_| None),
            lookahead_size: LOOKAHEAD_SIZE,
        };
        new_account.top_up_all()?;
        Ok(new_account)
    }

    /// Load all
    pub fn load_from_database(
        db: Arc<Store<B>>,
        account_pubkey: ExtendedPublicKey,
    ) -> KeyChainResult<Self> {
        // TODO remove this
        let _ = db.get_storage_version().expect("This should work?");
        let destinations = KeyPurpose::ALL.map(|_| BTreeMap::new());
        let last_used = KeyPurpose::ALL.map(|_| None);
        let last_issued = KeyPurpose::ALL.map(|_| None);

        // TODO implement loading from database
        Ok(AccountKeyChain {
            chain_config: Arc::new(create_regtest()),
            db,
            account_pubkey,
            account_privkey: None,
            destinations,
            last_used,
            last_issued,
            lookahead_size: LOOKAHEAD_SIZE,
        })
    }

    /// Get a new address that hasn't been used before
    pub fn get_new_address(&self, purpose: KeyPurpose) -> KeyChainResult<Address> {
        // self.destinations.get(purpose).expect();
        let key = self.get_new_key(purpose)?;

        let address = Address::from_public_key(&self.chain_config, &key.public_key())?;

        // TODO save address

        Ok(address)
    }

    /// Get a new derived key that hasn't been used before
    pub fn get_new_key(&self, purpose: KeyPurpose) -> KeyChainResult<ExtendedPublicKey> {
        let last_used = self.last_used[purpose as usize];

        // TODO implement with correct paths
        let hd_path = match purpose {
            KeyPurpose::ReceiveFunds => DerivationPath::from_str("m/0'/0'/0'/0'")?,
            KeyPurpose::Change => DerivationPath::from_str("m/0'/0'/1'/0'")?,
        };
        // TODO get key from a precalculated pool
        let new_key = self
            .account_privkey
            .as_ref()
            .ok_or(KeyChainError::MissingPrivateKey)?
            .clone()
            .derive_path(&hd_path)?;
        Ok(ExtendedPublicKey::from_private_key(&new_key))
    }

    /// Get the private key that corresponds to the provided public key
    pub(crate) fn get_key(&self, pk: &ExtendedPublicKey) -> KeyChainResult<ExtendedPrivateKey> {
        let account_privkey =
            self.account_privkey.clone().ok_or(KeyChainError::MissingPrivateKey)?;
        Ok(account_privkey.derive_path(pk.get_derivation_path())?)
    }

    /// Derive destinations until there are lookahead unused ones
    fn top_up_all(&mut self) -> KeyChainResult<()> {
        for purpose in KeyPurpose::ALL {
            self.top_up(purpose)?
        }
        Ok(())
    }

    /// Derive destinations for the `purpose` key chain
    fn top_up(&mut self, purpose: KeyPurpose) -> KeyChainResult<()> {
        let dest = &self.destinations[purpose as usize];
        println!("TODO topup {dest:?}");
        Ok(())
    }
}

/// Create a deterministic path for an account identified by the `account_index`
fn account_path(account_index: ChildNumber) -> DerivationPath {
    let mut path = Vec::with_capacity(ACCOUNTS_PATH.len() + 1);
    path.extend(ACCOUNTS_PATH);
    // path[..ACCOUNTS_PATH.len()].copy_from_slice(&ACCOUNTS_PATH);
    path.push(account_index);
    path.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::chain::config::create_unit_test_config;
    use test_utils::assert_encoded_eq;
    use wallet_storage::{DefaultBackend, Store};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn key_chain_creation() {
        let chain_config = Arc::new(create_unit_test_config());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
        let mut master_key_chain =
            MasterKeyChain::new_from_mnemonic(chain_config, db, MNEMONIC, None).unwrap();

        let key_chain = master_key_chain.get_default_account_key_chain().unwrap();

        // Sort test vectors by key_index i.e. the key with index 0 should be first
        let test_vec = vec![
            (
                KeyPurpose::ReceiveFunds,
                "m/0'/0'/0'/0'",
                "04feff4263658459430aea33cb851b830a0235db1611d3279624f40c7c2c0135",
                "1ac0ee91fe1ff500f4b21579cda6ded3b10a2f9162d571b4c8873454f3593326",
                "4fddb29b630431422b3a534e0028e053eb212ab10a5f1db3ba5cbc4e81ff3294",
            ),
            (
                KeyPurpose::Change,
                "m/0'/0'/1'/0'",
                "404dafb8e79d3110e816be00e020a91ef1754ab6b2ada14ec87a26f87e86e19e",
                "305f803928705f620e6a05dce2e4a6f8c03d1dc0757008096bf689160f394641",
                "04e13b373ed3d5753657d375feec032187cdada01e5df83cc8fddd29c1f15755",
            ),
        ];

        for (purpose, _hd_path, secret, public, chaincode) in test_vec {
            let pk = key_chain.get_new_key(purpose).unwrap();
            let sk = key_chain.get_key(&pk).unwrap();
            let pk = ExtendedPublicKey::from_private_key(&sk);
            // TODO assert that the hd_path is correct
            assert_encoded_eq(&sk, format!("00{chaincode}{secret}").as_str());
            assert_encoded_eq(&pk, format!("00{chaincode}{public}").as_str());
        }
    }
}
