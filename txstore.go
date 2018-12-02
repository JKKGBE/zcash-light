package zcash

import (
	"bytes"
	"log"
	"sync"
	"time"

	"github.com/OpenBazaar/multiwallet/keys"
	"github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

type TxStore struct {
	adrs           []btcutil.Address
	watchedScripts [][]byte
	txids          map[string]int32
	addrMutex      *sync.Mutex
	cbMutex        *sync.Mutex

	keyManager *keys.KeyManager

	params *chaincfg.Params

	listeners []func(wallet.TransactionCallback)

	wallet.Datastore
}

func NewTxStore(p *chaincfg.Params, db wallet.Datastore, keyManager *keys.KeyManager) (*TxStore, error) {
	txs := &TxStore{
		params:     p,
		keyManager: keyManager,
		addrMutex:  new(sync.Mutex),
		cbMutex:    new(sync.Mutex),
		txids:      make(map[string]int32),
		Datastore:  db,
	}
	err := txs.PopulateAdrs()
	if err != nil {
		return nil, err
	}
	return txs, nil
}

// GetDoubleSpends takes a transaction and compares it with
// all transactions in the db.  It returns a slice of all txids in the db
// which are double spent by the received tx.
func (ts *TxStore) CheckDoubleSpends(argTx *Transaction) ([]*chainhash.Hash, error) {
	var dubs []*chainhash.Hash // slice of all double-spent txs
	argTxid := argTx.TxHash()
	txs, err := ts.Txns().GetAll(true)
	if err != nil {
		return dubs, err
	}
	for _, compTx := range txs {
		if compTx.Height < 0 {
			continue
		}
		r := bytes.NewReader(compTx.Bytes)
		var msgTx Transaction
		if _, err := msgTx.ReadFrom(r); err != nil {
			return nil, err
		}
		compTxid := msgTx.TxHash()
		for _, argIn := range argTx.Inputs {
			// iterate through inputs of compTx
			for _, compIn := range msgTx.Inputs {
				if OutpointsEqual(argIn.PreviousOutPoint, compIn.PreviousOutPoint) && !compTxid.IsEqual(&argTxid) {
					// found double spend
					dubs = append(dubs, &compTxid)
					break // back to argIn loop
				}
			}
		}
	}
	return dubs, nil
}

// PopulateAdrs just puts a bunch of adrs in ram; it doesn't touch the DB
func (ts *TxStore) PopulateAdrs() error {
	keys := ts.keyManager.GetKeys()
	ts.addrMutex.Lock()
	ts.adrs = []btcutil.Address{}
	for _, k := range keys {
		addr, err := KeyToAddress(k, ts.params)
		if err != nil {
			continue
		}
		ts.adrs = append(ts.adrs, addr)
	}
	ts.watchedScripts, _ = ts.WatchedScripts().GetAll()
	txns, _ := ts.Txns().GetAll(true)
	for _, t := range txns {
		ts.txids[t.Txid] = t.Height
	}
	ts.addrMutex.Unlock()
	return nil
}

func (ts *TxStore) markAsDead(txid chainhash.Hash) error {
	stxos, err := ts.Stxos().GetAll()
	if err != nil {
		return err
	}
	markStxoAsDead := func(s wallet.Stxo) error {
		err := ts.Stxos().Delete(s)
		if err != nil {
			return err
		}
		err = ts.Txns().UpdateHeight(s.SpendTxid, -1, time.Now())
		if err != nil {
			return err
		}
		return nil
	}
	for _, s := range stxos {
		// If an stxo is marked dead, move it back into the utxo table
		if txid.IsEqual(&s.SpendTxid) {
			if err := markStxoAsDead(s); err != nil {
				return err
			}
			if err := ts.Utxos().Put(s.Utxo); err != nil {
				return err
			}
		}
		// If a dependency of the spend is dead then mark the spend as dead
		if txid.IsEqual(&s.Utxo.Op.Hash) {
			if err := markStxoAsDead(s); err != nil {
				return err
			}
			if err := ts.markAsDead(s.SpendTxid); err != nil {
				return err
			}
		}
	}
	utxos, err := ts.Utxos().GetAll()
	if err != nil {
		return err
	}
	// Dead utxos should just be deleted
	for _, u := range utxos {
		if txid.IsEqual(&u.Op.Hash) {
			err := ts.Utxos().Delete(u)
			if err != nil {
				return err
			}
		}
	}
	ts.Txns().UpdateHeight(txid, -1, time.Now())
	return nil
}

func (ts *TxStore) processReorg(lastGoodHeight uint32) error {
	txns, err := ts.Txns().GetAll(true)
	if err != nil {
		return err
	}
	for i := len(txns) - 1; i >= 0; i-- {
		if txns[i].Height > int32(lastGoodHeight) {
			txid, err := chainhash.NewHashFromStr(txns[i].Txid)
			if err != nil {
				log.Println(err)
				continue
			}
			err = ts.markAsDead(*txid)
			if err != nil {
				log.Println(err)
				continue
			}
		}
	}
	return nil
}

func (ts *TxStore) extractScriptAddress(script []byte) ([]byte, error) {
	addr, err := ExtractPkScriptAddrs(script, ts.params)
	if err != nil {
		return nil, err
	}
	return addr.ScriptAddress(), nil
}

func OutpointsEqual(a, b wire.OutPoint) bool {
	if !a.Hash.IsEqual(&b.Hash) {
		return false
	}
	return a.Index == b.Index
}
