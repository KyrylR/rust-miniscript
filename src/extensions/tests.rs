// SPDX-License-Identifier: CC0-1.0

use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{Keypair, SecretKey};
use elements::confidential::{Asset, Nonce, Value};
use elements::opcodes::all::{OP_ADD, OP_CHECKSIG, OP_CHECKSIGFROMSTACK, OP_EQUAL, OP_VERIFY};
use elements::taproot::TapLeafHash;
use elements::{LockTime, SchnorrSig, SchnorrSighashType};

use super::*;
use crate::miniscript::context::ScriptContextError;
use crate::miniscript::satisfy::Witness;
use crate::test_utils::StrXOnlyKeyTranslator;
use crate::{
    Legacy, Miniscript, ScriptContext, Segwitv0, Tap, Terminal, ValidationError,
    MAX_RECURSION_DEPTH,
};

type TapMs = Miniscript<XOnlyPublicKey, Tap, CovenantExt<CovExtArgs>>;

const MSG: &str = "f38b23e7d84506eb8eb477792ba607f908fe8a64ac9ae8dc0e760096e1550562";
const CONF_VALUE: &str = "09def814ab021498562ab4717287305d3f7abb5686832fe6183e1db495abef7cc7";
const SPK_V0: &str = "0014c73ac1b7a518499b9642aed8cfa15d5401e5bd85";
const SPK_P2SH: &str = "a914c73ac1b7a518499b9642aed8cfa15d5401e5bd8587";

fn keypair(byte: u8) -> Keypair {
    Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[byte; 32]).unwrap())
}

fn key(byte: u8) -> XOnlyPublicKey { keypair(byte).x_only_public_key().0 }

// Replaces `K1`, `K2`, ... by keys.
fn with_keys(s: &str) -> String {
    (1..=4).fold(s.to_owned(), |s, i| s.replace(&format!("K{}", i), &key(i).to_string()))
}

fn ext(s: &str) -> CovenantExt<CovExtArgs> {
    match TapMs::from_str_insane(&with_keys(s)).unwrap().as_inner() {
        Terminal::Ext(ext) => ext.clone(),
        node => panic!("{} is not an extension", node),
    }
}

// Two inputs spending explicit outputs of values 10 and 20; outputs of values 30 (explicit)
// and confidential. Input 1 issues 5 and 7 reissuance tokens.
fn transaction() -> (Transaction, Vec<TxOut>) {
    let asset: Asset = elements::encode::deserialize(&[1; 33]).unwrap();
    let txout = |value| TxOut {
        asset,
        value,
        nonce: Nonce::Null,
        script_pubkey: elements::Script::from_hex_no_prefix(SPK_V0).unwrap(),
        witness: Default::default(),
    };
    let conf_value = elements::encode::deserialize(&Vec::<u8>::from_hex(CONF_VALUE).unwrap());
    let mut issuing = TxIn::default();
    issuing.asset_issuance.amount = Value::Explicit(5);
    issuing.asset_issuance.inflation_keys = Value::Explicit(7);
    let tx = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default(), issuing],
        output: vec![txout(Value::Explicit(30)), txout(conf_value.unwrap())],
    };
    (tx, vec![txout(Value::Explicit(10)), txout(Value::Explicit(20))])
}

fn eval(s: &str, idx: usize) -> Result<bool, interpreter::Error> {
    let (tx, utxos) = transaction();
    let env = TxEnv::new(&tx, &utxos, idx).unwrap();
    ext(s).evaluate(&mut Stack::from(vec![]), Some(&env))
}

fn eval_err(s: &str) -> EvalError {
    match eval(s, 1) {
        Err(interpreter::Error::Extension(e)) => e,
        res => panic!("{}: {:?}", s, res.map_err(|e| e.to_string())),
    }
}

#[test]
fn string_and_script_roundtrip() {
    let ms = [
        "csfs(K1,MSG)".replace("MSG", MSG),
        "and_v(v:csfs(K1,MSG),pk(K2))".replace("MSG", MSG),
        "and_v(v:pk(K1),is_exp_asset(inp_asset(idx_sub(idx_add(curr_idx,1),1))))".into(),
        "and_v(v:pk(K1),asset_eq(curr_inp_asset,out_asset(idx_mul(2,idx_div(curr_idx,3)))))".into(),
        format!("and_v(v:pk(K1),value_eq({},out_value(1)))", CONF_VALUE),
        "and_v(v:pk(K1),is_exp_value(010000000011110000))".into(),
        format!("and_v(v:pk(K1),spk_eq({},out_spk(0)))", SPK_V0),
        "and_v(v:pk(K1),curr_idx_eq(3))".into(),
        "and_v(v:idx_eq(10,idx_add(9,curr_idx)),pk(K1))".into(),
        "and_v(v:pk(K1),num64_geq(sub(mul(1,0),mul(0,curr_inp_v)),-5))".into(),
        "and_v(v:pk(K1),num64_eq(mod(inp_issue_v(0),3),inp_reissue_v(1)))".into(),
        "and_v(v:pk(K1),num64_lt(bitand(bitinv(1),bitxor(2,bitor(3,4))),neg(5)))".into(),
        "and_v(v:num64_eq(8,8),pk(K1))".into(),
        "and_v(v:pk(K1),num64_eq(add(price_oracle1(K2,123),price_oracle1_w(K3,7)),div(out_v(0),2)))"
            .into(),
    ];
    for s in ms.iter().map(|s| with_keys(s)) {
        let ms = TapMs::from_str_insane(&s).unwrap();
        assert_eq!(ms.to_string(), s);
        let script = ms.encode();
        assert_eq!(TapMs::decode_consensus(&script).unwrap(), ms, "{}", s);
        // Constants are sized at their largest, a 32-byte commitment.
        assert!(ms.script_size() >= script.len(), "{}", s);
        if !s.contains("010000000011110000") && !s.contains(SPK_V0) {
            assert_eq!(ms.script_size(), script.len(), "{}", s);
        }
    }
}

// Script does not distinguish an operand at index `curr_idx` from the current-input form.
#[test]
fn current_input_operands_decode_as_current_input_forms() {
    for (s, decoded) in [
        ("idx_eq(5,curr_idx)", "curr_idx_eq(5)"),
        ("num64_eq(inp_v(curr_idx),1)", "num64_eq(curr_inp_v,1)"),
        ("is_exp_asset(inp_asset(curr_idx))", "is_exp_asset(curr_inp_asset)"),
        ("is_exp_value(inp_value(curr_idx))", "is_exp_value(curr_inp_value)"),
        ("spk_eq(inp_spk(curr_idx),out_spk(0))", "spk_eq(curr_inp_spk,out_spk(0))"),
    ] {
        let script = TapMs::from_str_insane(s).unwrap().encode();
        assert_eq!(TapMs::decode_consensus(&script).unwrap().to_string(), decoded);
    }
}

#[test]
fn script_only_constants() {
    // A non-witness script pubkey is pushed as its hash, which decodes to that hash only.
    let s = with_keys(&format!("and_v(v:pk(K1),spk_eq({},out_spk(0)))", SPK_P2SH));
    let script = TapMs::from_str_insane(&s).unwrap().encode();
    let decoded = TapMs::decode_consensus(&script).unwrap();
    assert_eq!(decoded.encode(), script);
    assert!(decoded.to_string().contains("hashed_spk("));
}

#[test]
fn extensions_are_tapscript_only() {
    let s = with_keys("and_v(v:pk(K1),curr_idx_eq(0))");
    type SegwitMs = Miniscript<bitcoin::PublicKey, Segwitv0, CovenantExt<CovExtArgs>>;
    let not_allowed = Error::ContextError(ScriptContextError::ExtensionNotAllowed).to_string();
    let compressed = s.replace(&key(1).to_string(), &format!("02{}", key(1)));
    assert_eq!(
        SegwitMs::from_str_insane(&compressed)
            .unwrap_err()
            .to_string(),
        not_allowed
    );
    let keyless = TapMs::from_str_insane("curr_idx_eq(0)").unwrap().encode();
    assert_eq!(
        SegwitMs::decode_consensus(&keyless)
            .unwrap_err()
            .to_string(),
        not_allowed
    );
    let script = TapMs::from_str_insane(&s).unwrap().encode();
    // Without the extension, the fragments are not Miniscript.
    assert!(Miniscript::<XOnlyPublicKey, Tap>::from_str_insane(&s).is_err());
    assert!(Miniscript::<XOnlyPublicKey, Tap>::decode_consensus(&script).is_err());
}

#[test]
fn csfs_message_is_32_bytes() {
    assert!(TapMs::from_str_insane(&with_keys(&format!("csfs(K1,{})", &MSG[2..]))).is_err());
    assert!(TapMs::from_str_insane(&with_keys(&format!("csfs(K1,{}00)", MSG))).is_err());
}

#[test]
fn csfs_verify_is_one_opcode() {
    let msg = CsfsMsg::from_slice(&[7; 32]).unwrap();
    let script = Builder::new()
        .push_slice(msg.as_inner())
        .push_slice(&key(1).serialize())
        .push_opcode(OP_CHECKSIGFROMSTACK)
        .push_opcode(OP_VERIFY)
        .push_slice(&key(2).serialize())
        .push_opcode(OP_CHECKSIG)
        .into_script();
    assert!(matches!(
        TapMs::decode_consensus(&script),
        Err(Error::ScriptLexer(crate::miniscript::lex::Error::NonMinimalVerify(_)))
    ));
}

#[test]
fn deep_index_scripts_fail_to_decode() {
    let mut builder = Builder::new().push_int(1);
    for _ in 0..1000 {
        builder = builder.push_int(1).push_opcode(OP_ADD);
    }
    let script = builder.push_int(1).push_opcode(OP_EQUAL).into_script();
    assert!(TapMs::decode_consensus(&script).is_err());
}

#[test]
fn csfs_consumes_the_top_signature() {
    let msg = Message::from_digest([7; 32]);
    let csfs = ext(&format!("csfs(K1,{})", msg));
    let sig = Secp256k1::new()
        .sign_schnorr_no_aux_rand(&msg, &keypair(1))
        .serialize();
    let below = [9; 64];

    let mut stack = Stack::from(vec![Element::Push(&below), Element::Push(&sig)]);
    assert!(csfs.evaluate(&mut stack, None).unwrap());
    assert_eq!(stack.pop(), Some(Element::Push(&below)));
    assert!(stack.is_empty());

    let mut stack = Stack::from(vec![Element::Push(&sig), Element::Dissatisfied]);
    assert!(!csfs.evaluate(&mut stack, None).unwrap());

    let mut stack = Stack::from(vec![Element::Push(&sig), Element::Push(&below)]);
    assert!(matches!(
        csfs.evaluate(&mut stack, None),
        Err(interpreter::Error::InvalidSchnorrSignature(_))
    ));
}

#[test]
fn index_evaluation() {
    assert!(eval("idx_eq(curr_idx,1)", 1).unwrap());
    assert!(!eval("curr_idx_eq(0)", 1).unwrap());
    // Euclidean division, and negative values that are not used as indexes.
    assert!(eval("idx_eq(idx_div(idx_sub(0,7),2),idx_sub(0,4))", 0).unwrap());
    assert!(eval("asset_eq(inp_asset(idx_div(idx_mul(curr_idx,2),2)),out_asset(0))", 1).unwrap());

    assert_eq!(eval_err("idx_eq(idx_div(1,0),0)"), EvalError::DivByZero);
    assert_eq!(eval_err("idx_eq(idx_mul(2147483647,2),0)"), EvalError::IndexOverflow);
    assert!(!eval("idx_eq(idx_add(2147483647,1),0)", 0).unwrap());
    assert!(eval("idx_eq(idx_add(2147483647,1),idx_add(2147483647,1))", 0).unwrap());
    assert!(
        eval("idx_eq(idx_sub(idx_sub(0,2147483647),1),idx_sub(idx_sub(0,2147483647),1))", 0)
            .unwrap()
    );
    assert_eq!(eval_err("idx_eq(idx_add(idx_add(2147483647,1),0),0)"), EvalError::IndexOverflow);
    assert_eq!(
        eval_err("is_exp_asset(inp_asset(idx_add(2147483647,1)))"),
        EvalError::IndexOverflow
    );
    assert_eq!(eval_err("is_exp_asset(inp_asset(idx_sub(0,1)))"), EvalError::NegativeIndex(-1));
    assert_eq!(eval_err("is_exp_asset(inp_asset(2))"), EvalError::InputIndexOutOfBounds(2, 2));
    assert_eq!(eval_err("is_exp_value(out_value(2))"), EvalError::OutputIndexOutOfBounds(2, 2));
    // Constants must fit a script number.
    assert!(TapMs::from_str_insane("curr_idx_eq(2147483648)").is_err());
    assert!(TapMs::from_str_insane("idx_eq(01,1)").is_err());
}

#[test]
fn introspection_evaluation() {
    assert!(eval("is_exp_value(inp_value(1))", 0).unwrap());
    assert!(!eval("is_exp_value(out_value(1))", 0).unwrap());
    assert!(eval(&format!("value_eq(out_value(1),{})", CONF_VALUE), 0).unwrap());
    // The serialized explicit value 10, pushed little-endian.
    assert!(eval("value_eq(inp_value(0),01000000000000000a)", 0).unwrap());
    assert!(!eval("value_eq(inp_value(0),01000000000000000b)", 0).unwrap());
    assert!(eval(&format!("spk_eq(curr_inp_spk,{})", SPK_V0), 0).unwrap());
    assert!(!eval(&format!("spk_eq(curr_inp_spk,{})", SPK_P2SH), 0).unwrap());
}

#[test]
fn arithmetic_evaluation() {
    assert!(eval("num64_eq(add(inp_v(0),curr_inp_v),out_v(0))", 1).unwrap());
    assert!(eval("num64_eq(div(-7,2),-4)", 0).unwrap());
    assert!(eval("num64_eq(mod(-7,2),1)", 0).unwrap());
    assert!(eval("num64_eq(inp_issue_v(1),5)", 0).unwrap());
    assert!(eval("num64_eq(inp_reissue_v(1),7)", 0).unwrap());
    assert!(eval("num64_eq(bitinv(0),-1)", 0).unwrap());

    let min = i64::MIN;
    let max = i64::MAX;
    assert_eq!(eval_err(&format!("num64_eq(add({},1),0)", max)), EvalError::AddOverflow(max, 1));
    assert_eq!(eval_err(&format!("num64_eq(sub({},1),0)", min)), EvalError::SubOverflow(min, 1));
    assert_eq!(eval_err(&format!("num64_eq(mul({},2),0)", max)), EvalError::MulOverflow(max, 2));
    assert_eq!(eval_err("num64_eq(div(1,0),0)"), EvalError::DivByZero);
    assert_eq!(eval_err("num64_eq(mod(1,0),0)"), EvalError::DivByZero);
    assert_eq!(
        eval_err(&format!("num64_eq(div({},-1),0)", min)),
        EvalError::DivOverflow(min, -1)
    );
    assert_eq!(
        eval_err(&format!("num64_eq(mod({},-1),0)", min)),
        EvalError::DivOverflow(min, -1)
    );
    assert_eq!(eval_err(&format!("num64_eq(neg({}),0)", min)), EvalError::NegOverflow(min));
    assert_eq!(eval_err("num64_eq(out_v(1),0)"), EvalError::NonExplicitOutput(1));
    assert_eq!(eval_err("num64_eq(inp_issue_v(0),0)"), EvalError::NonExplicitInputIssuance(0));
    assert!(TapMs::from_str_insane("num64_eq(-0,0)").is_err());
    assert!(TapMs::from_str_insane("num64_eq(9223372036854775808,0)").is_err());
}

#[test]
fn null_issuance_amounts_are_zero() {
    let (mut tx, utxos) = transaction();
    for (amount, tokens, fragment) in [
        (Value::Explicit(5), Value::Null, "num64_eq(inp_reissue_v(1),0)"),
        (Value::Null, Value::Explicit(7), "num64_eq(inp_issue_v(1),0)"),
    ] {
        tx.input[1].asset_issuance.amount = amount;
        tx.input[1].asset_issuance.inflation_keys = tokens;
        let env = TxEnv::new(&tx, &utxos, 0).unwrap();
        assert!(ext(fragment)
            .evaluate(&mut Stack::from(vec![]), Some(&env))
            .unwrap());
    }
    tx.input[1].asset_issuance = Default::default();
    let env = TxEnv::new(&tx, &utxos, 0).unwrap();
    for fragment in ["num64_eq(inp_issue_v(1),0)", "num64_eq(inp_reissue_v(1),0)"] {
        assert!(ext(fragment)
            .evaluate(&mut Stack::from(vec![]), Some(&env))
            .is_err());
    }
}

// For an input without an issuance, `INSPECTINPUTISSUANCE` pushes one empty item. The nonce
// size check fails on it, before the amount could be read from witness items below it.
#[test]
fn issuance_expressions_check_the_nonce_size() {
    let script = |hex: &str| elements::Script::from_hex_no_prefix(hex).unwrap();
    for (s, guarded, unguarded) in [
        (
            "num64_eq(inp_issue_v(0),42)",
            "00cc82012088757551887777082a0000000000000087",
            "00cc757551887777082a0000000000000087",
        ),
        (
            "num64_eq(inp_reissue_v(0),42)",
            "00cc82012088757575755188082a0000000000000087",
            "00cc757575755188082a0000000000000087",
        ),
    ] {
        assert_eq!(TapMs::from_str_insane(s).unwrap().encode(), script(guarded), "{}", s);
        assert!(TapMs::decode_consensus(&script(unguarded)).is_err(), "{}", s);
    }
}

#[test]
fn null_values_use_the_explicit_zero_stack_encoding() {
    let (mut tx, mut utxos) = transaction();
    tx.output[0].value = Value::Null;
    utxos[0].value = Value::Null;
    let env = TxEnv::new(&tx, &utxos, 0).unwrap();
    for fragment in [
        "is_exp_value(curr_inp_value)",
        "value_eq(curr_inp_value,010000000000000000)",
        "is_exp_value(out_value(0))",
        "value_eq(out_value(0),010000000000000000)",
        "num64_eq(curr_inp_v,0)",
        "num64_eq(out_v(0),0)",
    ] {
        assert!(ext(fragment)
            .evaluate(&mut Stack::from(vec![]), Some(&env))
            .unwrap());
    }
}

#[test]
fn null_value_constants_decode_as_explicit_zero() {
    let null = TapMs::from_str_insane("value_eq(00,out_value(0))").unwrap();
    let zero = TapMs::from_str_insane("value_eq(010000000000000000,out_value(0))").unwrap();
    assert_eq!(null.encode(), zero.encode());
    assert_eq!(TapMs::decode_consensus(&null.encode()).unwrap(), zero);
}

#[test]
fn index_constants_check_the_script_number_limit() {
    let max = IdxConst::new(i32::MAX as u32).unwrap();
    for op in [
        CovOps::curr_idx_eq(max),
        CovOps::idx_eq(IdxExpr::CurrIdx, IdxExpr::Const(max)).unwrap(),
    ] {
        let ms = TapMs::from_ast(Terminal::Ext(CovenantExt::Introspect(Box::new(op)))).unwrap();
        assert_eq!(TapMs::decode_consensus(&ms.encode()).unwrap(), ms);
        assert_eq!(TapMs::from_str_insane(&ms.to_string()).unwrap(), ms);
    }
    assert!(IdxConst::new(i32::MAX as u32 + 1).is_err());
    assert!(IdxConst::new(u32::MAX).is_err());
}

// The constructors limit nesting as decoding does, so that the recursive methods of a fragment
// cannot exhaust the stack.
#[test]
fn constructors_limit_operand_depth() {
    fn too_deep<T>(result: Result<T, Error>) -> bool {
        matches!(result, Err(Error::MaxRecursiveDepthExceeded))
    }
    let limit = MAX_RECURSION_DEPTH as usize;
    let idx = |depth: usize| {
        let mut x = IdxExpr::CurrIdx;
        for _ in 0..depth {
            x = IdxExpr::Add(Box::new(x), Box::new(IdxExpr::CurrIdx));
        }
        x
    };
    let negated = |depth: usize| {
        let mut x = Expr::<CovExtArgs>::Const(1);
        for _ in 0..depth {
            x = Expr::Negate(Box::new(x));
        }
        x
    };
    let comparison = |left| Arith::new(Comparison::Eq, left, Expr::<CovExtArgs>::Const(1));

    CovOps::<CovExtArgs>::idx_eq(idx(limit), IdxExpr::CurrIdx).unwrap();
    assert!(too_deep(CovOps::<CovExtArgs>::idx_eq(IdxExpr::CurrIdx, idx(limit + 1))));
    CovOps::<CovExtArgs>::value_eq(FieldExpr::Output(idx(limit)), FieldExpr::CurrInput).unwrap();
    assert!(too_deep(CovOps::<CovExtArgs>::value_eq(
        FieldExpr::CurrInput,
        FieldExpr::Input(idx(limit + 1))
    )));
    comparison(negated(limit)).unwrap();
    assert!(too_deep(comparison(negated(limit + 1))));
    comparison(Expr::Input(idx(limit - 1))).unwrap();
    assert!(too_deep(comparison(Expr::Input(idx(limit)))));
}

#[test]
fn transaction_conditions_need_the_transaction() {
    assert!(matches!(
        ext("curr_idx_eq(0)").evaluate(&mut Stack::from(vec![]), None),
        Err(interpreter::Error::Extension(EvalError::TxEnvNotPresent))
    ));
    let (tx, utxos) = transaction();
    assert!(TxEnv::new(&tx, &utxos[..1], 0).is_none());
    assert!(TxEnv::new(&tx, &utxos, 2).is_none());
}

#[test]
fn spent_outputs_are_borrowed() {
    let (tx, utxos) = transaction();
    let refs: Vec<&TxOut> = utxos.iter().collect();
    let sum = ext("num64_eq(add(inp_v(0),curr_inp_v),out_v(0))");
    let envs = [
        TxEnv::new(&tx, &utxos, 1).unwrap(),
        TxEnv::from_refs(&tx, &refs, 1).unwrap(),
        TxEnv::from_iter(&tx, &utxos, 1).unwrap(),
    ];
    for env in envs {
        assert!(core::ptr::eq(env.spent_utxo(1).unwrap(), &utxos[1]));
        assert_eq!(env.spent_utxo(2), Err(EvalError::InputIndexOutOfBounds(2, 2)));
        assert!(sum.evaluate(&mut Stack::from(vec![]), Some(&env)).unwrap());
    }
    assert!(TxEnv::from_refs(&tx, &refs[..1], 0).is_none());
    assert!(TxEnv::from_refs(&tx, &refs, 2).is_none());
    assert!(TxEnv::from_iter(&tx, &utxos[..1], 0).is_none());
    assert!(TxEnv::from_iter(&tx, &utxos, 2).is_none());
}

#[test]
fn validation_rejects_extensions_outside_tapscript() {
    let ms = TapMs::from_str_insane("curr_idx_eq(0)").unwrap();
    assert_eq!(ms.validate(&Tap::CONSENSUS), Ok(()));
    assert_eq!(ms.validate(&Segwitv0::CONSENSUS), Err(ValidationError::IllegalExtension));
    assert_eq!(ms.validate(&Legacy::CONSENSUS), Err(ValidationError::IllegalExtension));
}

#[test]
fn oracle_positions() {
    for s in [
        "num64_eq(price_oracle1_w(K1,1),1)",
        "num64_eq(1,price_oracle1(K1,1))",
        "num64_eq(add(1,price_oracle1(K1,1)),1)",
        "num64_eq(add(1,add(2,price_oracle1_w(K1,1))),1)",
        "num64_eq(price_oracle1(K1,1),price_oracle1(K2,1))",
    ] {
        assert!(TapMs::from_str_insane(&with_keys(s)).is_err(), "{}", s);
    }
    for s in [
        "num64_eq(price_oracle1(K1,1),price_oracle1_w(K2,1))",
        "num64_eq(add(1,price_oracle1_w(K1,1)),1)",
        "num64_eq(neg(price_oracle1(K1,1)),1)",
    ] {
        assert!(TapMs::from_str_insane(&with_keys(s)).is_ok(), "{}", s);
    }
}

#[test]
fn oracle_attestations() {
    // An attestation from the Fuji price oracle.
    let sig = schnorr::Signature::from_str("8fc6e217b0e1d3481855cdb97cfe333999d4cf48b9f58b4f299ad86fd768a345e97a953d6efa1ca5971f18810deedcfddc4c2bd4e8f9d1431c1ad6ebafa013a9").unwrap();
    let pk = XOnlyPublicKey::from_str(
        "c304c3b5805eecff054c319c545dc6ac2ad44eb70f79dd9570e284c5a62c0f9e",
    )
    .unwrap();
    let secp = Secp256k1::verification_only();
    assert!(check_sig_price_oracle_1(&secp, &sig, &pk, 1679531858733, 27365));
    assert!(!check_sig_price_oracle_1(&secp, &sig, &pk, 1679531858733, 27366));

    let arith = ext("num64_eq(price_oracle1(K1,100),27365)");
    let attest = |timestamp: u64, price: u64| {
        let msg = sighash_msg_price_oracle_1(timestamp, price);
        Secp256k1::new()
            .sign_schnorr_no_aux_rand(&msg, &keypair(1))
            .serialize()
    };
    let (tx, utxos) = transaction();
    let env = TxEnv::new(&tx, &utxos, 0).unwrap();
    let run = |sig: &[u8], timestamp: u64, price: u64| {
        let (timestamp, price) = (timestamp.to_le_bytes(), price.to_le_bytes());
        let mut stack = Stack::from(vec![
            Element::Push(sig),
            Element::Push(&timestamp),
            Element::Push(&price),
        ]);
        arith
            .evaluate(&mut stack, Some(&env))
            .map_err(|e| e.to_string())
    };

    assert_eq!(run(&attest(100, 27365), 100, 27365), Ok(true));
    assert_eq!(run(&attest(150, 27000), 150, 27000), Ok(false));
    let too_early = EvalError::OracleTimestampTooEarly { timestamp: 99, min_timestamp: 100 };
    assert_eq!(
        run(&attest(99, 27365), 99, 27365),
        Err(format!("covenant evaluation: {}", too_early))
    );
    // Timestamps compare as signed numbers.
    let negative = 1 << 63;
    assert!(run(&attest(negative, 27365), negative, 27365).is_err());
    // The signature covers the timestamp and price that the witness holds.
    let invalid = interpreter::Error::Extension(EvalError::InvalidOracleSignature).to_string();
    assert_eq!(run(&attest(100, 27365), 101, 27365), Err(invalid.clone()));
    assert_eq!(run(&attest(100, 27365), 100, 27366), Err(invalid));
    assert!(matches!(
        arith.evaluate(&mut Stack::from(vec![]), Some(&env)),
        Err(interpreter::Error::Extension(EvalError::MissingOracleWitness))
    ));
}

// A satisfier with a signature for every key, csfs signatures, and the Fuji oracle.
struct TestSatisfier<'tx> {
    env: Option<TxEnv<'tx, 'tx>>,
    csfs: bool,
}

impl Satisfier<XOnlyPublicKey> for TestSatisfier<'_> {
    fn lookup_tap_leaf_script_sig(
        &self,
        _: &XOnlyPublicKey,
        _: &TapLeafHash,
    ) -> Option<SchnorrSig> {
        let sig = schnorr::Signature::from_slice(&[1; 64]).unwrap();
        Some(SchnorrSig { sig, hash_ty: SchnorrSighashType::Default })
    }

    fn lookup_tx_env(&self) -> Option<&TxEnv<'_, '_>> { self.env.as_ref() }

    fn lookup_csfs_sig(&self, _: &XOnlyPublicKey, _: &CsfsMsg) -> Option<schnorr::Signature> {
        self.csfs
            .then(|| schnorr::Signature::from_slice(&[2; 64]).unwrap())
    }

    fn lookup_price_oracle_sig(
        &self,
        pk: &XOnlyPublicKey,
        min_timestamp: u64,
    ) -> Option<(schnorr::Signature, i64, u64)> {
        let sig = schnorr::Signature::from_slice(&pk.serialize().repeat(2)).ok()?;
        Some((sig, 10, min_timestamp))
    }
}

fn template(s: &str, env: Option<TxEnv>, csfs: bool) -> Witness<Placeholder<XOnlyPublicKey>> {
    TapMs::from_str_insane(&with_keys(s))
        .unwrap()
        .build_template(&TestSatisfier { env, csfs })
        .stack
}

#[test]
fn templates() {
    let (tx, utxos) = transaction();
    let env = |idx| TxEnv::new(&tx, &utxos, idx);
    let signed = "and_v(v:pk(K1),curr_idx_eq(1))";

    // Unknown without the transaction; with it, a signature fixes the outcome.
    assert_eq!(template(signed, None, false), Witness::Unavailable);
    assert!(matches!(template(signed, env(1), false), Witness::Stack(ref s) if s.len() == 1));
    assert_eq!(template(signed, env(0), false), Witness::Impossible);
    assert_eq!(template("curr_idx_eq(1)", env(0), false), Witness::Unavailable);
    assert_eq!(template("num64_eq(div(1,0),0)", env(0), false), Witness::Unavailable);
    assert_eq!(
        template("and_v(v:pk(K1),num64_eq(div(1,0),0))", env(0), false),
        Witness::Impossible
    );

    let csfs = format!("csfs(K1,{})", MSG);
    let msg = CsfsMsg::from_slice(&Vec::<u8>::from_hex(MSG).unwrap()).unwrap();
    assert_eq!(
        template(&csfs, None, true),
        Witness::Stack(vec![Placeholder::CsfsSig(key(1), msg)])
    );
    assert_eq!(template(&csfs, None, false), Witness::Unavailable);

    // The first attestation that the script consumes is on top.
    let oracles = "num64_eq(add(price_oracle1(K1,1),price_oracle1_w(K2,2)),20)";
    let data = |k: u8, timestamp: u64| {
        let sig = key(k).serialize().repeat(2);
        [
            sig,
            timestamp.to_le_bytes().to_vec(),
            10i64.to_le_bytes().to_vec(),
        ]
        .map(Placeholder::Data)
    };
    let mut expected = data(2, 2).to_vec();
    expected.extend(data(1, 1));
    assert_eq!(template(oracles, env(0), false), Witness::Stack(expected));
    assert_eq!(template(&oracles.replace("20", "21"), env(0), false), Witness::Unavailable);
    assert_eq!(template(&oracles.replace("20", "21"), env(0), true), Witness::Unavailable);
}

// A CSFS signature commits to its message, not to the transaction, so whoever has seen it can
// reuse it in another transaction.
#[test]
fn csfs_is_not_a_transaction_signature() {
    let (tx, utxos) = transaction();
    let env = |idx| TxEnv::new(&tx, &utxos, idx);
    let with_csfs = TestSatisfier { env: None, csfs: true };
    let without_csfs = TestSatisfier { env: None, csfs: false };

    let csfs = with_keys(&format!("csfs(K1,{})", MSG));
    let alone = TapMs::from_str_insane(&csfs).unwrap();
    assert!(!alone.non_malleable_and_requires_sig());
    assert!(matches!(
        TapMs::from_str(&csfs),
        Err(Error::Validation(ValidationError::SiglessBranch))
    ));
    assert!(!alone.build_template(&with_csfs).has_sig);
    assert_eq!(alone.satisfy(&with_csfs).unwrap(), vec![vec![2; 64]]);

    // The fixed-message signature can be replayed, so a third party can build a transaction
    // that meets the condition, and an unmet condition is unavailable rather than impossible.
    let reused = format!("and_v(v:csfs(K1,{}),curr_idx_eq(1))", MSG);
    assert_eq!(template(&reused, env(0), true), Witness::Unavailable);
    assert!(matches!(template(&reused, env(1), true), Witness::Stack(ref s) if s.len() == 1));

    // A key signature commits to the transaction.
    let signed = format!("and_v(v:pk(K2),{})", reused);
    assert!(TapMs::from_str(&with_keys(&signed))
        .unwrap()
        .non_malleable_and_requires_sig());
    assert_eq!(template(&signed, env(0), true), Witness::Impossible);
    assert!(matches!(template(&signed, env(1), true), Witness::Stack(ref s) if s.len() == 2));

    // A missing CSFS signature may be known to others, so a non-malleable satisfaction cannot
    // avoid its branch, while a malleable one uses the key.
    let either =
        TapMs::from_str_insane(&with_keys(&format!("or_b(csfs(K1,{}),s:pk(K2))", MSG))).unwrap();
    assert_eq!(either.build_template(&without_csfs).stack, Witness::Unavailable);
    assert!(matches!(either.build_template_mall(&without_csfs).stack, Witness::Stack(_)));
}

#[test]
fn translation_checks_arguments() {
    struct Args;

    impl ExtParamTranslator<String> for Args {
        type TargetArg = CovExtArgs;
        type Error = ();

        fn ext(&mut self, arg: &String) -> Result<CovExtArgs, ()> {
            match arg.as_str() {
                "X" => Ok(CovExtArgs::csfs_key(key(1))),
                "msg" => Ok(CovExtArgs::csfs_msg(Message::from_digest([7; 32]))),
                "spk" => Ok(CovExtArgs::spk(elements::Script::from_hex_no_prefix(SPK_V0).unwrap())),
                _ => Err(()),
            }
        }
    }

    let ms = Miniscript::<String, Tap, CovenantExt<String>>::from_str_insane(
        "and_v(v:pk(A),and_v(v:csfs(X,msg),spk_eq(spk,out_spk(0))))",
    )
    .unwrap();
    let ms = ms.translate_pk(&mut StrXOnlyKeyTranslator::new()).unwrap();
    let ms = ms.translate_ext(&mut Args).unwrap();
    assert_eq!(TapMs::from_str_insane(&ms.to_string()).unwrap(), ms);

    let swapped = Miniscript::<String, Tap, CovenantExt<String>>::from_str_insane("csfs(msg,X)")
        .unwrap()
        .translate_pk(&mut StrXOnlyKeyTranslator::new())
        .unwrap();
    assert!(matches!(swapped.translate_ext(&mut Args), Err(TranslateErr::OuterError(_))));
    let unknown = Miniscript::<String, Tap, CovenantExt<String>>::from_str_insane("csfs(X,m)")
        .unwrap()
        .translate_pk(&mut StrXOnlyKeyTranslator::new())
        .unwrap();
    assert!(matches!(unknown.translate_ext(&mut Args), Err(TranslateErr::TranslatorErr(()))));
}
