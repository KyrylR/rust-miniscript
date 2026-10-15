#![allow(unexpected_cfgs)]

use honggfuzz::fuzz;
use miniscript::elements::{LockTime, Script, Sequence, Witness};
use miniscript::Interpreter;

// The data is a list of witness items, each after a one-byte length. The last item is the
// witness script that the scriptPubKey pays to.
fn do_test(data: &[u8]) {
    let mut items = vec![];
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        let (item, tail) = tail.split_at(usize::from(len).min(tail.len()));
        items.push(item.to_vec());
        rest = tail;
    }
    let Some(witness_script) = items.last() else {
        return;
    };
    let spk = Script::from(witness_script.clone()).to_v0_p2wsh();
    let script_sig = Script::new();
    let witness = Witness::from_slice(&items);

    if let Ok(interpreter) =
        Interpreter::from_txdata(&spk, &script_sig, &witness, Sequence::ZERO, LockTime::ZERO)
    {
        for _ in interpreter.iter_assume_sigs() {}
    }
}

fn main() {
    loop {
        fuzz!(|data| {
            do_test(data);
        });
    }
}
