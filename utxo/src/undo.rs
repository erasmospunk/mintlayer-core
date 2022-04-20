#![allow(unused, dead_code)]

use crate::Utxo;
use parity_scale_codec::{Decode, Encode};

#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct TxUndo(Vec<Utxo>);

impl TxUndo {
    pub fn new(utxos:Vec<Utxo>) -> Self {
        Self(utxos)
    }

    pub fn inner(&self) -> &[Utxo] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<Utxo> {
        self.0
    }
}


#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct BlockUndo(Vec<TxUndo>);

impl BlockUndo {
    pub fn new(tx_undos:Vec<TxUndo>) -> Self {
        Self(tx_undos)
    }

    pub fn inner(&self) -> &[TxUndo] {
        &self.0
    }

    pub fn into_inner(self) -> Vec<TxUndo> {
        self.0
    }
}

#[cfg(test)]
pub mod test {
    use crypto::random::{make_pseudo_rng, Rng};
    use crate::test_helper::create_utxo;
    use super::*;

    #[test]
    fn tx_undo_test() {
        let (utxo0,_) = create_utxo(0);
        let (utxo1,_) = create_utxo(1);
        let tx_undo = TxUndo::new(vec![utxo0.clone(), utxo1.clone()]);

        // check `inner()`
        {
            let inner = tx_undo.inner();
            assert_eq!(&utxo0, &inner[0]);
            assert_eq!(&utxo1, &inner[1]);
        }

        // check `into_inner()`
        {
            let undo_vec = tx_undo.into_inner();
            assert_eq!(&utxo0, &undo_vec[0]);
            assert_eq!(&utxo1, &undo_vec[1]);
        }

    }

    #[test]
    fn block_undo_test() {
        let (utxo0,_) = create_utxo(0);
        let (utxo1,_) = create_utxo(1);
        let tx_undo0 = TxUndo::new(vec![utxo0,utxo1]);

        let (utxo2,_) = create_utxo(2);
        let (utxo3,_) = create_utxo(3);
        let (utxo4,_) = create_utxo(4);
        let tx_undo1 = TxUndo::new(vec![utxo2,utxo3, utxo4]);

        let blockundo = BlockUndo::new( vec![tx_undo0, tx_undo1]);

        // check `inner()`
        {
            let inner =  blockundo.inner();

            assert_eq!(&tx_undo0, &inner[0]);
            assert_eq!(&tx_undo1, &inner[1]);
        }

        // check `into_inter`
        {
            let inner = blockundo.into_inner();
            assert_eq!(&tx_undo0, &inner[0]);
            assert_eq!(&tx_undo1, &inner[1]);
        }

    }
}