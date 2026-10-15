// SPDX-License-Identifier: CC0-1.0

//! Curly braces are only accepted around the branches of Taproot script trees.

use std::fmt;
use std::str::FromStr;

use elements_miniscript::bitcoin::PublicKey;
use elements_miniscript::{confidential, DescriptorPublicKey, Error, ParseError, ParseTreeError};

type Descriptor = elements_miniscript::Descriptor<PublicKey>;

const PK: &str = "03774eec7a3d550d18e9f89414152025b3b0ad6a342b19481f702d843cff06dfc4";
const NUMS: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
const CT_KEY: &str = "02dce16018bbbb8e36de7b394df5b5166e9adb7498be7d881a85a09aeecf76b623";
const MBK: &str = "b2396b3ee20509cdb64fe24180a14a72dbd671728eaa49bac69d2bdecb5f5a04";
const XPRV: &str = "xprv9s21ZrQH143K28NgQ7bHCF61hy9VzwquBZvpzTwXLsbmQLRJ6iV9k2hUBRt5qzmBaSpeMj5LdcsHaXJvM7iFEivPryRcL8irN7Na9p65UUb";
const SPK_XPUB: &str = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";

/// Checks that `s` parses, and that it is rejected whenever any one pair of its round
/// brackets is replaced with curly braces.
fn check_curly_braces<T>(s: &str)
where
    T: FromStr,
    T::Err: fmt::Debug,
{
    T::from_str(s).unwrap();

    let mut open = vec![];
    let mut n_variants = 0;
    for (pos, ch) in s.char_indices() {
        match ch {
            '(' => open.push(pos),
            ')' => {
                let mut variant = s.as_bytes().to_vec();
                variant[open.pop().unwrap()] = b'{';
                variant[pos] = b'}';
                let variant = String::from_utf8(variant).unwrap();
                assert!(T::from_str(&variant).is_err(), "accepted {}", variant);
                n_variants += 1;
            }
            _ => {}
        }
    }
    assert!(n_variants > 0);
}

// The key of `elwpkh`, `elpkh` and `elsh(wpkh)` is read without parsing it as Miniscript, so
// the brackets around it are checked separately.
#[test]
fn descriptors() {
    for s in [
        format!("elwpkh({PK})"),
        format!("elpkh({PK})"),
        format!("elsh(wpkh({PK}))"),
        format!("elsh(wsh(pk({PK})))"),
        format!("elwsh(or_d(pk({PK}),and_v(v:pk({NUMS}),older(10))))"),
        format!("eltr({NUMS},{{{{pk({PK}),pk({NUMS})}},pk({CT_KEY})}})"),
    ] {
        check_curly_braces::<Descriptor>(&s);
    }

    for s in [
        format!("elwpkh{{{PK}}}"),
        format!("elpkh{{{PK}}}"),
        format!("elsh(wpkh{{{PK}}})"),
        format!("elwsh(or_d(pk({PK}),{{pk({NUMS}),older(10)}}))"),
    ] {
        assert!(
            matches!(
                Descriptor::from_str(&s),
                Err(Error::Parse(ParseError::Tree(ParseTreeError::IllegalCurlyBrace { .. })))
            ),
            "{}",
            s
        );
    }
}

#[test]
fn confidential_descriptors() {
    for s in [
        format!("ct(slip77({MBK}),elwsh(or_d(pk({PK}),and_v(v:pk({NUMS}),older(10)))))"),
        format!("ct({PK},eltr({NUMS},{{pk({PK}),pk({NUMS})}}))"),
        format!("ct(slip77({MBK}),elwpkh({PK}))"),
        format!("ct({XPRV},elpkh({PK}))"),
        format!("ct(elip151,elsh(wpkh({SPK_XPUB}/*)))"),
    ] {
        check_curly_braces::<confidential::Descriptor<DescriptorPublicKey>>(&s);
    }
}
