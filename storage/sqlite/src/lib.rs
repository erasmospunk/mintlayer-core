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

mod error;

use rusqlite::{Connection, OpenFlags, Transaction};
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use storage_core::error::Fatal;
use storage_core::{
    backend::{self, TransactionalRo, TransactionalRw},
    info::{DbDesc, MapDesc},
    Data, DbIndex,
};
use utils::sync::{Arc, RwLock, RwLockReadGuard};

/// Identifiers of the list of databases (key-value maps)
#[derive(Eq, PartialEq, Debug, Clone)]
struct DbList(Vec<()>);

impl std::ops::Index<DbIndex> for DbList {
    type Output = ();

    fn index(&self, index: DbIndex) -> &Self::Output {
        &self.0[index.get()]
    }
}

/// LMDB iterator over entries with given key prefix
pub struct PrefixIter<'tx, C> {
    /// Underlying iterator
    iter: C,

    /// Prefix to iterate over
    prefix: Data,

    // TODO remove
    _phantom: PhantomData<&'tx ()>,
}

impl<'tx, C> PrefixIter<'tx, C> {
    fn new(iter: C, prefix: Data) -> Self {
        PrefixIter {
            iter,
            prefix,
            _phantom: PhantomData,
        }
    }
}

impl<'tx, C> Iterator for PrefixIter<'tx, C> {
    type Item = (Data, Data);

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
        // let (k, v) = self.iter.next()?.expect("iteration to proceed");
        // utils::ensure!(k.starts_with(&self.prefix));
        // Some((k.to_vec(), v.to_vec()))
    }
}

pub struct DbTx<'m> {
    // conn: MutexGuard<'m, Connection>,
    tx: Transaction<'m>,
    // dbs: &'m DbList,
    // _map_token: RwLockReadGuard<'m, remap::MemMapController>,
}

// type DbTxRo<'a> = DbTx<'a, Transaction<'a>>;
// type DbTxRw<'a> = DbTx<'a, Transaction<'a>>;

impl<'s, 'i> backend::PrefixIter<'i> for DbTx<'s> {
    type Iterator = PrefixIter<'i, ()>;

    fn prefix_iter<'t: 'i>(
        &'t self,
        idx: DbIndex,
        prefix: Data,
    ) -> storage_core::Result<Self::Iterator> {
        todo!()
        // let cursor = self.tx.open_ro_cursor(self.dbs[idx]).or_else(error::process_with_err)?;
        // let iter = if prefix.is_empty() {
        //     cursor.into_iter_start()
        // } else {
        //     cursor.into_iter_from(prefix.as_slice())
        // };
        // Ok(PrefixIter::new(iter, prefix))
    }
}

impl backend::ReadOps for DbTx<'_> {
    fn get(&self, idx: DbIndex, key: &[u8]) -> storage_core::Result<Option<&[u8]>> {
        todo!()
        // self.tx
        //     .get(self.dbs[idx], &key)
        //     .map_or_else(error::process_with_none, |x| Ok(Some(x)))
    }
}

impl backend::WriteOps for DbTx<'_> {
    fn put(&mut self, idx: DbIndex, key: Data, val: Data) -> storage_core::Result<()> {
        todo!()
        // self.tx
        //     .put(self.dbs[idx], &key, &val, lmdb::WriteFlags::empty())
        //     .or_else(error::process_with_unit)
    }

    fn del(&mut self, idx: DbIndex, key: &[u8]) -> storage_core::Result<()> {
        todo!()
        // self.tx.del(self.dbs[idx], &key, None).or_else(error::process_with_unit)
    }
}

impl backend::TxRo for DbTx<'_> {}

impl backend::TxRw for DbTx<'_> {
    fn commit(self) -> storage_core::Result<()> {
        todo!()
        // lmdb::Transaction::commit(self.tx).or_else(error::process_with_unit)
    }
}

#[derive(Clone)]
pub struct SqliteImpl {
    /// Handle to an Sqlite database connection
    connection: Arc<Mutex<Connection>>,
    // /// List of open databases
    // dbs: DbList,
    // _phantom: PhantomData<&'conn ()>,
}

impl SqliteImpl {
    /// Start a transaction using the low-level method provided
    fn start_transaction<'a>(
        &'a self,
        // start_tx: impl FnOnce(&'a ()) -> Result<Transaction<'a>, rusqlite::Error>,
    ) -> storage_core::Result<DbTx<'a>> {
        // todo!()

        // TODO implement properly
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| storage_core::error::Recoverable::TemporarilyUnavailable)?;
        let mut tx = connection.transaction().map_err(error::process_sqlite_error)?;
        Ok(DbTx {
            // conn: connection,
            tx,
        })

        // // Make sure map token is acquired before starting the transaction below
        // let _map_token = self.map_token.read().expect("mutex to be alive");
        // Ok(DbTx {
        //     tx: start_tx(&self.env).or_else(error::process_with_err)?,
        //     dbs: &self.dbs,
        //     _map_token,
        // })
    }
}

// impl<'tx> TransactionalRo<'tx> for SqliteImpl {
//     type TxRo = DbTx<'tx>;
impl<'tx> TransactionalRo<'tx> for SqliteImpl {
    type TxRo = DbTx<'tx>;

    fn transaction_ro<'st: 'tx>(&'st self) -> storage_core::Result<Self::TxRo> {
        self.start_transaction()
    }
}

impl<'tx> TransactionalRw<'tx> for SqliteImpl {
    type TxRw = DbTx<'tx>;

    fn transaction_rw<'st: 'tx>(&'st self) -> storage_core::Result<Self::TxRw> {
        self.start_transaction()
    }
}

impl backend::BackendImpl for SqliteImpl {}
// impl backend::BackendImpl for SqliteImpl<'_> {}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Sqlite {
    path: PathBuf,
}

impl Sqlite {
    /// New Sqlite database backend
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    // fn open_db(self, desc: &MapDesc) -> storage_core::Result<Connection> {
    fn open_db(self) -> storage_core::Result<Connection> {
        let flags = OpenFlags::from_iter([
            OpenFlags::SQLITE_OPEN_FULL_MUTEX,
            OpenFlags::SQLITE_OPEN_READ_WRITE,
            OpenFlags::SQLITE_OPEN_CREATE,
        ]);

        // // TODO change error
        let connection = Connection::open_with_flags(self.path, flags)
            .map_err(|err| Fatal::InternalError(err.to_string()))?;

        Ok(connection)

        // let flags = lmdb::DatabaseFlags::default();
        // env.create_db(name, flags).or_else(error::process_with_err)
    }
}

impl backend::Backend for Sqlite {
    type Impl = SqliteImpl;

    fn open(self, desc: DbDesc) -> storage_core::Result<Self::Impl> {
        // Attempt to create the parent storage directory
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(error::process_io_error)?;
        } else {
            return Err(storage_core::error::Recoverable::Io(
                std::io::ErrorKind::NotFound,
                "Cannot find the parent directory".to_string(),
            )
            .into());
        }

        // // Set up LMDB environment
        // let environment = lmdb::Environment::new()
        //     .set_max_dbs(desc.len() as u32)
        //     .set_flags(self.flags)
        //     .set_map_size(self.map_size.as_bytes())
        //     .open(&self.path)
        //     .or_else(error::process_with_err)?;

        // // Set up all the databases
        // let dbs = desc
        //     .iter()
        //     .map(|desc| Self::open_db(&environment, desc))
        //     .collect::<storage_core::Result<Vec<_>>>()
        //     .map(DbList)?;

        let connection = self.open_db()?;

        Ok(SqliteImpl {
            connection: Arc::new(Mutex::new(connection)),
            // dbs,
            // map_token: Arc::new(RwLock::new(remap::MemMapController::new())),
            // tx_size: self.tx_size,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::Sqlite;
    use storage_backend_test_suite::prelude::IDX;
    use storage_core::backend::{ReadOps, TransactionalRo, TransactionalRw, TxRw, WriteOps};
    use storage_core::info::MapDesc;
    use storage_core::{Backend, DbDesc};

    /// Sample database description with `n` maps
    pub fn desc(n: usize) -> DbDesc {
        (0..n).map(|x| MapDesc::new(format!("map_{:02}", x))).collect()
    }

    #[test]
    fn put_and_commit() {
        let test_root = test_utils::test_root!("backend-tests").unwrap();
        let test_dir = test_root.fresh_test_dir("unknown");
        let mut db_file = test_dir.as_ref().to_path_buf();
        db_file.set_file_name("database.sqlite");
        println!("db_file.to_str() = {:?}", db_file.file_name().unwrap());

        // let sqlite = Sqlite::new(test_dir.as_ref().to_path_buf().with_file_name("database.sqlite"));
        let sqlite = Sqlite::new(db_file);

        let store = sqlite.open(desc(1)).expect("db open to succeed");

        // Create a transaction, modify storage and abort transaction
        let mut dbtx = store.transaction_rw().unwrap();
        dbtx.put(IDX.0, b"hello".to_vec(), b"world".to_vec()).unwrap();
        dbtx.commit().expect("commit to succeed");

        // Check the modification did not happen
        let dbtx = store.transaction_ro().unwrap();
        assert_eq!(dbtx.get(IDX.0, b"hello"), Ok(Some(b"world".as_ref())));
        drop(dbtx);
    }
}
