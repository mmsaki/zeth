//! Minimal revm runner for the cross-client benchmark. revm is the EVM engine
//! reth uses, so this measures "reth's EVM". Given a hex program it executes it
//! repeatedly and prints `gas <code_gas> ns <min_ns>` (matching zeth-run).

use revm::{
    db::{CacheDB, EmptyDB},
    primitives::{AccountInfo, Address, Bytecode, Bytes, ExecutionResult, TxKind, U256},
    Evm,
};
use std::time::Instant;

const WARMUP: usize = 3;
const SAMPLES: usize = 25;
const INTRINSIC_GAS: u64 = 21_000; // base tx cost; subtracted to match raw-code gas

fn main() {
    let hexcode = std::env::args().nth(1).expect("usage: revm-runner <hex>");
    let code = hex::decode(hexcode.trim_start_matches("0x")).expect("invalid hex");

    let bytecode = Bytecode::new_raw(Bytes::from(code));
    let target = Address::from([0x10u8; 20]);

    let mut db = CacheDB::new(EmptyDB::default());
    db.insert_account_info(
        target,
        AccountInfo {
            balance: U256::ZERO,
            nonce: 0,
            code_hash: bytecode.hash_slow(),
            code: Some(bytecode),
        },
    );

    let mut evm = Evm::builder()
        .with_db(db)
        .modify_tx_env(|tx| {
            tx.transact_to = TxKind::Call(target);
            tx.gas_limit = 1_000_000_000_000;
        })
        .build();

    let mut best = u128::MAX;
    let mut gas = 0u64;
    for i in 0..(WARMUP + SAMPLES) {
        let t0 = Instant::now();
        let out = evm.transact().expect("transact failed");
        let dt = t0.elapsed().as_nanos();
        gas = out.result.gas_used();
        if i >= WARMUP {
            best = best.min(dt);
        }
    }

    // The program has no calldata, so code gas = total - 21000 intrinsic.
    println!("gas {} ns {}", gas.saturating_sub(INTRINSIC_GAS), best);
}
