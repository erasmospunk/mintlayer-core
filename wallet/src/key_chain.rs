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
//! m/44'/19788'/<account_number>'/<key_purpose>'/<key_index>'
//!
//! Where 44' is the standard BIP44 prefix
//!       19788' or 0x4D4C' (1' for the testnets) is Mintlayer's BIP44 registered coin type
//!       `account_number` is the index of an account,
//!       `key_purpose` is if the generated address is for receiving or change purposes and this
//!                     value is 0 or 1 respectively,
//!       `key_index` starts from 0 and it is incremented for each new address

use common::address::{Address, AddressError};
use common::chain::config::{create_regtest, BIP44_PATH};
use common::chain::{ChainConfig, Destination};
use crypto::key::extended::{ExtendedKeyKind, ExtendedPrivateKey, ExtendedPublicKey};
use crypto::key::hdkd::child_number::ChildNumber;
use crypto::key::hdkd::derivable::{Derivable, DerivationError};
use crypto::key::hdkd::derivation_path::DerivationPath;
use crypto::key::hdkd::u31::U31;
use crypto::key::PublicKey;
use serialization::{Decode, Encode};
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::sync::Arc;
use storage::Backend;
use wallet_storage::{Store, WalletStorageRead};
use zeroize::Zeroize;

/// Size of the tree leading to accounts paths: m/44'/<coin_type>'
const COIN_TYPE_TREE_DEPTH: usize = 2;
/// Size of individual account key tree: account_number, key_purpose, key_index
const ACCOUNT_KEY_TREE_DEPTH: usize = 3;
/// The maximum derivation path length
const BIP44_ACCOUNT_KEY_TREE_DEPTH: usize = COIN_TYPE_TREE_DEPTH + ACCOUNT_KEY_TREE_DEPTH;
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
    #[error("Invalid BIP44 account path format: {0}")]
    InvalidBip44AccountPath(DerivationPath),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum AccountKeyId {
    Derived(AccountHDPath),
}

/// The AccountHDPath is is used for identifying entries belonging to a specific account.
/// The format of the path should follow the BIP32 specification
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
        let path = pk.get_derivation_path();
        if path.len() != BIP44_ACCOUNT_KEY_TREE_DEPTH {
            return Err(KeyChainError::InvalidBip44AccountPath(path));
        }

        let path = path.into_vec();

        let key_index = path[4];
        let key_purpose = path[3];
        let account_number = path[2];
        let coin_type = path[1];
        let bip44_index = path[0];

        // Check that the path confirms to the spec
        if bip44_index != BIP44_PATH
            || coin_type.is_normal()
            || account_number.is_normal()
            || key_purpose.is_hardened()
            || key_index.is_hardened()
        {
            return Err(KeyChainError::InvalidBip44AccountPath(
                pk.get_derivation_path(),
            ));
        }

        Ok(AccountHDPath::new(account_number, key_purpose, key_index))
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
    /// The index for each purpose
    const DETERMINISTIC_INDEX: [ChildNumber; 2] = [
        ChildNumber::from_normal(U31::from_u32_ignore_msb(0)),
        ChildNumber::from_normal(U31::from_u32_ignore_msb(1)),
    ];
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum KeyChainId {
    Master(PublicKey),
    Account(PublicKey),
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

        Ok(MasterKeyChain {
            chain_config,
            root_key,
            db,
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

        // TODO implement loading from database
        Ok(MasterKeyChain {
            chain_config,
            root_key: master_key,
            db,
        })
    }

    pub fn create_account_key_chain(
        &self,
        account_index: ChildNumber,
    ) -> KeyChainResult<AccountKeyChain<B>> {
        AccountKeyChain::new_from_root_key(
            self.chain_config.clone(),
            self.db.clone(),
            &self.root_key,
            account_index,
        )
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
    destinations: [BTreeMap<ChildNumber, Destination>; KeyPurpose::ALL.len()],

    /// Last used destination index per `KeyPurpose`. A destination might not be used so the
    /// corresponding entry would be None, otherwise it would be that last used ChildNumber
    last_used: [Option<ChildNumber>; KeyPurpose::ALL.len()],

    /// Last issued destination to the user
    last_issued: [Option<ChildNumber>; KeyPurpose::ALL.len()],

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
        let account_path = make_account_path(&chain_config, num);

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
    pub fn load_from_database(db: Arc<Store<B>>, id: KeyChainId) -> KeyChainResult<Self> {
        // TODO remove this
        let _ = db.get_storage_version().expect("This should work?");
        let (account_privkey, account_pubkey) =
            ExtendedPrivateKey::new_from_entropy(ExtendedKeyKind::Secp256k1Schnorr);
        let destinations = KeyPurpose::ALL.map(|_| BTreeMap::new());
        let last_used = KeyPurpose::ALL.map(|_| None);
        let last_issued = KeyPurpose::ALL.map(|_| None);

        // TODO implement loading from database
        Ok(AccountKeyChain {
            chain_config: Arc::new(create_regtest()),
            db,
            account_pubkey,
            account_privkey: Some(account_privkey),
            destinations,
            last_used,
            last_issued,
            lookahead_size: LOOKAHEAD_SIZE,
        })
    }

    pub fn get_id(&self) -> KeyChainId {
        KeyChainId::Account(self.account_pubkey.clone().into_public_key())
    }

    /// Get a new address that hasn't been used before
    pub fn get_new_address(&mut self, purpose: KeyPurpose) -> KeyChainResult<Address> {
        // self.destinations.get(purpose).expect();
        let key = self.get_new_key(purpose)?;

        let address = Address::from_public_key(&self.chain_config, &key.into_public_key())?;

        // TODO save address

        Ok(address)
    }

    /// Get a new derived key that hasn't been used before
    pub fn get_new_key(&mut self, purpose: KeyPurpose) -> KeyChainResult<ExtendedPublicKey> {
        let new_last_used = {
            match self.last_used[purpose as usize] {
                None => ChildNumber::ZERO,
                Some(last_used) => last_used.plus_one()?,
            }
        };

        // The path of the new key
        let key_path = {
            let mut path = self.account_pubkey.get_derivation_path().into_vec();
            path.push(KeyPurpose::DETERMINISTIC_INDEX[purpose as usize]);
            path.push(new_last_used);
            path.try_into()?
        };

        // TODO get key from a precalculated pool
        let new_key = self
            .account_privkey
            .as_ref()
            .ok_or(KeyChainError::MissingPrivateKey)?
            .clone()
            .derive_path(&key_path)?;
        self.last_used[purpose as usize] = Some(new_last_used);
        // TODO save last_used to db

        Ok(ExtendedPublicKey::from_private_key(&new_key))
    }

    /// Get the private key that corresponds to the provided public key
    pub(crate) fn get_key(&self, pk: &ExtendedPublicKey) -> KeyChainResult<ExtendedPrivateKey> {
        let account_privkey =
            self.account_privkey.clone().ok_or(KeyChainError::MissingPrivateKey)?;
        Ok(account_privkey.derive_path(&pk.get_derivation_path())?)
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
fn make_account_path(chain_config: &ChainConfig, account_index: ChildNumber) -> DerivationPath {
    // The path is m/44'/<coin_type>'/<account_index>'
    let path = vec![BIP44_PATH, chain_config.bip44_index(), account_index];
    path.try_into().expect("Path creation should not fail")
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::chain::config::create_unit_test_config;
    use std::str::FromStr;
    use test_utils::assert_encoded_eq;
    use wallet_storage::{DefaultBackend, Store};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn key_chain_creation() {
        let chain_config = Arc::new(create_unit_test_config());
        let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
        let master_key_chain =
            MasterKeyChain::new_from_mnemonic(chain_config, db, MNEMONIC, None).unwrap();

        let mut key_chain = master_key_chain.create_account_key_chain(ChildNumber::ZERO_H).unwrap();

        // Sort test vectors by key_index i.e. the key with index 0 should be first
        let test_vec = vec![
            (
                KeyPurpose::ReceiveFunds,
                "m/44'/19788'/0'/0/0",
                "8000002c80004d4c800000000000000000000000",
                "b870ce52f8ccb3204e7fcdbb84f122fee29ce3c462750c54d411201baa4cf23c",
                "03bf6f8d52dade77f95e9c6c9488fd8492a99c09ff23095caffb2e6409d1746ade",
                "0ae454a1024d0ddb9e10d23479cf8ef39fb400727fabd17844bd8362b1c70d7d",
            ),
            (
                KeyPurpose::Change,
                "m/44'/19788'/0'/1/0",
                "8000002c80004d4c800000000000000100000000",
                "f2b1cb7118920fe9b3a0470bd67588fb4bdd4af1355ff39171ed41e968a8621b",
                "035df5d551bac1d61a5473615a70eb17b2f4ccbf7e354166639428941e4dbbcd81",
                "8d62d08e7a23e4b510b970ffa84b4a5ed22e6c03faecf32c5dafaf092938516d",
            ),
            (
                KeyPurpose::ReceiveFunds,
                "m/44'/19788'/0'/0/1",
                "8000002c80004d4c800000000000000000000001",
                "f73943cf443cd5cdd6c35e3fc1c8f039dd92c29a3d9fc1f56c5145ad67535fba",
                "030d1d07a8e45110d14f4e2c8623e8db556c11a90c0aac6be9a88f2464e446ee95",
                "7ed12073a4cc61d8a79f3dc0dfc5ca1a23d9ce1fe3c1e92d3b6939cd5848a390",
            ),
        ];

        for (purpose, path_str, path_encoded_str, secret, public, chaincode) in test_vec {
            let pk = key_chain.get_new_key(purpose).unwrap();
            assert_eq!(pk.get_derivation_path().to_string(), path_str.to_string());
            let sk = key_chain.get_key(&pk).unwrap();
            let pk2 = ExtendedPublicKey::from_private_key(&sk);
            assert_eq!(pk2.get_derivation_path().to_string(), path_str.to_string());
            assert_eq!(pk, pk2);
            let path = DerivationPath::from_str(path_str).unwrap();
            assert_eq!(sk.get_derivation_path(), path);
            assert_eq!(pk.get_derivation_path(), path);
            let path_len = path.len();
            assert_encoded_eq(
                &sk,
                format!("00{path_len:02x}{path_encoded_str}{chaincode}{secret}").as_str(),
            );
            assert_encoded_eq(
                &pk,
                format!("00{path_len:02x}{path_encoded_str}{chaincode}{public}").as_str(),
            );
        }
    }
}
