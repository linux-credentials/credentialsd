//! In-memory CTAP2 authenticator for testing credentialsd without hardware.
//!
//! Only compiled with the `test-authenticator` cargo feature, only offered when
//! `CREDSD_TEST_AUTHENTICATOR=1` is set, and only for requests from
//! [`ALLOWED_ORIGINS`]. Keys live in memory and are lost when credentialsd
//! exits. It is plugged into the USB flow as a libwebauthn virtual HID device.
//!
//! User presence and user verification are assumed: choosing the device in
//! the credentialsd UI is the only interaction. Do not use it for real
//! accounts.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::OnceLock,
};

use libwebauthn::transport::hid::{
    HidDevice, HidPipeBackend,
    framing::{HidCommand, HidMessage},
    virtual_device,
};
use ring::{
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};
use serde_cbor_2::Value;

pub(crate) const ENV_VAR: &str = "CREDSD_TEST_AUTHENTICATOR";

/// Test sites the authenticator is offered to. Requests from any other origin
/// never see it.
pub(crate) const ALLOWED_ORIGINS: &[&str] = &["https://webauthn.io", "https://demo.yubico.com"];

fn origin_allowed(origin: &str) -> bool {
    ALLOWED_ORIGINS.contains(&origin)
}

/// Whether to offer the authenticator, given the value of [`ENV_VAR`].
fn offered(env: Option<&std::ffi::OsStr>, origin: &str) -> bool {
    env.is_some_and(|v| v == "1") && origin_allowed(origin)
}

/// The virtual device, when the authenticator is enabled and `origin` is allowed.
///
/// All requests share one authenticator, so credentials last until
/// credentialsd exits.
pub(crate) fn device_for_origin(origin: &str) -> Option<HidDevice> {
    static DEVICE: OnceLock<HidDevice> = OnceLock::new();
    if !offered(std::env::var_os(ENV_VAR).as_deref(), origin) {
        return None;
    }
    tracing::warn!(origin, "Offering the in-memory test authenticator");
    Some(
        DEVICE
            .get_or_init(|| virtual_device(TestAuthenticator::default()))
            .clone(),
    )
}

const BROADCAST_CID: u32 = 0xffff_ffff;
const CAPABILITY_CBOR: u8 = 0x04;
const CAPABILITY_NMSG: u8 = 0x08;
/// All-zero AAGUID: no attestation, "none" format.
const AAGUID: [u8; 16] = [0; 16];

const CMD_MAKE_CREDENTIAL: u8 = 0x01;
const CMD_GET_ASSERTION: u8 = 0x02;
const CMD_GET_INFO: u8 = 0x04;
const CMD_GET_NEXT_ASSERTION: u8 = 0x08;

const OK: u8 = 0x00;
const ERR_INVALID_COMMAND: u8 = 0x01;
const ERR_INVALID_CBOR: u8 = 0x12;
const ERR_MISSING_PARAMETER: u8 = 0x14;
const ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
const ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const ERR_INVALID_OPTION: u8 = 0x2c;
const ERR_NO_CREDENTIALS: u8 = 0x2e;
const ERR_NOT_ALLOWED: u8 = 0x30;
const ERR_PIN_NOT_SET: u8 = 0x35;
const ERR_OTHER: u8 = 0x7f;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;
const COSE_ES256: i128 = -7;

struct Credential {
    id: Vec<u8>,
    rp_id: String,
    user_id: Vec<u8>,
    user_name: Option<String>,
    user_display_name: Option<String>,
    discoverable: bool,
    key: EcdsaKeyPair,
    counter: u32,
}

/// Remaining credentials for authenticatorGetNextAssertion.
struct PendingAssertions {
    cid: u32,
    rp_id: String,
    client_hash: Vec<u8>,
    flags: u8,
    remaining: VecDeque<usize>,
}

#[derive(Default)]
pub(crate) struct TestAuthenticator {
    credentials: Vec<Credential>,
    pending: Option<PendingAssertions>,
    /// Replies waiting for `recv`. libwebauthn does not say which channel a
    /// `recv` is for, so this assumes one ceremony at a time, which is how
    /// credentialsd runs them.
    replies: VecDeque<HidMessage>,
    last_cid: u32,
}

impl std::fmt::Debug for TestAuthenticator {
    // Hand-written so key material never reaches the logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestAuthenticator")
            .field("credentials", &self.credentials.len())
            .finish_non_exhaustive()
    }
}

impl HidPipeBackend for TestAuthenticator {
    fn send(&mut self, msg: &HidMessage) {
        let reply = match msg.cmd {
            HidCommand::Init => Some(self.init(msg)),
            HidCommand::Ping => Some(HidMessage::new(msg.cid, HidCommand::Ping, &msg.payload)),
            HidCommand::Wink => Some(HidMessage::new(msg.cid, HidCommand::Wink, &[])),
            HidCommand::Cbor => Some(HidMessage::new(
                msg.cid,
                HidCommand::Cbor,
                &self.cbor(msg.cid, &msg.payload),
            )),
            // Every request is answered at once, so there is nothing to cancel.
            HidCommand::Cancel => None,
            _ => Some(HidMessage::new(
                msg.cid,
                HidCommand::Error,
                &[ERR_INVALID_COMMAND],
            )),
        };
        self.replies.extend(reply);
    }

    fn recv(&mut self) -> HidMessage {
        self.replies.pop_front().unwrap_or_else(|| {
            tracing::warn!("Test authenticator asked for a reply it does not have");
            HidMessage::new(self.last_cid, HidCommand::Error, &[ERR_OTHER])
        })
    }
}

impl TestAuthenticator {
    fn init(&mut self, msg: &HidMessage) -> HidMessage {
        if msg.cid == BROADCAST_CID {
            // 0 and the broadcast CID are reserved.
            self.last_cid = match self.last_cid.wrapping_add(1) {
                0 | BROADCAST_CID => 1,
                cid => cid,
            };
        } else {
            self.last_cid = msg.cid;
        }
        let mut payload = msg.payload.clone();
        payload.extend(self.last_cid.to_be_bytes());
        // CTAPHID protocol 2, device version 0.1.0, capabilities.
        payload.extend([2, 0, 1, 0, CAPABILITY_CBOR | CAPABILITY_NMSG]);
        HidMessage::new(msg.cid, HidCommand::Init, &payload)
    }

    /// One authenticatorXxx command: status byte followed by the CBOR response.
    fn cbor(&mut self, cid: u32, payload: &[u8]) -> Vec<u8> {
        let Some((&cmd, body)) = payload.split_first() else {
            return vec![ERR_INVALID_COMMAND];
        };
        let params = if body.is_empty() {
            Ok(BTreeMap::new())
        } else {
            match serde_cbor_2::from_slice(body) {
                Ok(Value::Map(m)) => Ok(m),
                _ => Err(ERR_INVALID_CBOR),
            }
        };
        if cmd != CMD_GET_NEXT_ASSERTION {
            self.pending = None;
        }
        let result = params.and_then(|p| match cmd {
            CMD_GET_INFO => Ok(get_info()),
            CMD_MAKE_CREDENTIAL => self.make_credential(&p),
            CMD_GET_ASSERTION => self.get_assertion(cid, &p),
            CMD_GET_NEXT_ASSERTION => self.get_next_assertion(cid),
            _ => Err(ERR_INVALID_COMMAND),
        });
        match result.and_then(|v| serde_cbor_2::to_vec(&v).map_err(|_| ERR_OTHER)) {
            Ok(body) => [&[OK][..], &body].concat(),
            Err(code) => vec![code],
        }
    }

    fn make_credential(&mut self, p: &BTreeMap<Value, Value>) -> Result<Value, u8> {
        // clientDataHash is required, but only signed in attestations ("none" here).
        get(p, 1).and_then(as_bytes).ok_or(ERR_MISSING_PARAMETER)?;
        let rp = get(p, 2).ok_or(ERR_MISSING_PARAMETER)?;
        let rp_id = entry(rp, "id")
            .and_then(as_text)
            .ok_or(ERR_MISSING_PARAMETER)?;
        let user = get(p, 3).ok_or(ERR_MISSING_PARAMETER)?;
        let user_id = entry(user, "id")
            .and_then(as_bytes)
            .ok_or(ERR_MISSING_PARAMETER)?;
        let Some(Value::Array(algorithms)) = get(p, 4) else {
            return Err(ERR_MISSING_PARAMETER);
        };
        pin_auth(get(p, 8))?;
        if !algorithms
            .iter()
            .any(|a| entry(a, "alg") == Some(&Value::Integer(COSE_ES256)))
        {
            return Err(ERR_UNSUPPORTED_ALGORITHM);
        }
        let options = get(p, 7);
        if option(options, "up") == Some(false) {
            return Err(ERR_INVALID_OPTION);
        }
        let rk = option(options, "rk").unwrap_or(false);
        let uv = option(options, "uv").unwrap_or(false);
        if let Some(exclude) = credential_ids(get(p, 5))
            && self
                .credentials
                .iter()
                .any(|c| c.rp_id == rp_id && exclude.contains(&c.id.as_slice()))
        {
            return Err(ERR_CREDENTIAL_EXCLUDED);
        }

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| ERR_OTHER)?;
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .map_err(|_| ERR_OTHER)?;
        let mut id = vec![0; 16];
        rng.fill(&mut id).map_err(|_| ERR_OTHER)?;

        let mut auth_data = auth_data(rp_id, FLAG_UP | FLAG_AT | uv_flag(uv), 0);
        auth_data.extend(AAGUID);
        auth_data.extend((id.len() as u16).to_be_bytes());
        auth_data.extend(&id);
        auth_data.extend(cose_key(key.public_key().as_ref()));

        if rk {
            self.credentials
                .retain(|c| !(c.discoverable && c.rp_id == rp_id && c.user_id == user_id));
        }
        self.credentials.push(Credential {
            id,
            rp_id: rp_id.to_owned(),
            user_id: user_id.to_vec(),
            user_name: entry(user, "name").and_then(as_text).map(str::to_owned),
            user_display_name: entry(user, "displayName")
                .and_then(as_text)
                .map(str::to_owned),
            discoverable: rk,
            key,
            counter: 0,
        });
        Ok(int_map([
            (1, Value::Text("none".to_owned())),
            (2, Value::Bytes(auth_data)),
            (3, Value::Map(BTreeMap::new())),
        ]))
    }

    fn get_assertion(&mut self, cid: u32, p: &BTreeMap<Value, Value>) -> Result<Value, u8> {
        let rp_id = get(p, 1).and_then(as_text).ok_or(ERR_MISSING_PARAMETER)?;
        let client_hash = get(p, 2).and_then(as_bytes).ok_or(ERR_MISSING_PARAMETER)?;
        pin_auth(get(p, 6))?;
        let options = get(p, 5);
        let up = option(options, "up").unwrap_or(true);
        let uv = option(options, "uv").unwrap_or(false);
        let flags = if up { FLAG_UP } else { 0 } | uv_flag(uv);

        let allow = credential_ids(get(p, 3));
        // Newest first, so the most recent registration is offered first.
        let mut matches: VecDeque<usize> = (0..self.credentials.len())
            .rev()
            .filter(|&i| {
                let c = &self.credentials[i];
                c.rp_id == rp_id
                    && match &allow {
                        Some(ids) => ids.contains(&c.id.as_slice()),
                        None => c.discoverable,
                    }
            })
            .collect();
        let first = matches.pop_front().ok_or(ERR_NO_CREDENTIALS)?;
        let total = (allow.is_none() && !matches.is_empty()).then_some(matches.len() + 1);
        let response = self.assertion(first, rp_id, client_hash, flags, total)?;
        if total.is_some() {
            self.pending = Some(PendingAssertions {
                cid,
                rp_id: rp_id.to_owned(),
                client_hash: client_hash.to_vec(),
                flags,
                remaining: matches,
            });
        }
        Ok(response)
    }

    fn get_next_assertion(&mut self, cid: u32) -> Result<Value, u8> {
        let pending = self
            .pending
            .as_mut()
            .filter(|p| p.cid == cid)
            .ok_or(ERR_NOT_ALLOWED)?;
        let next = pending.remaining.pop_front().ok_or(ERR_NOT_ALLOWED)?;
        let (rp_id, client_hash, flags) = (
            pending.rp_id.clone(),
            pending.client_hash.clone(),
            pending.flags,
        );
        if pending.remaining.is_empty() {
            self.pending = None;
        }
        self.assertion(next, &rp_id, &client_hash, flags, None)
    }

    fn assertion(
        &mut self,
        index: usize,
        rp_id: &str,
        client_hash: &[u8],
        flags: u8,
        total: Option<usize>,
    ) -> Result<Value, u8> {
        let c = &mut self.credentials[index];
        c.counter = c.counter.wrapping_add(1);
        let auth_data = auth_data(rp_id, flags, c.counter);
        let signature = c
            .key
            .sign(
                &SystemRandom::new(),
                &[&auth_data[..], client_hash].concat(),
            )
            .map_err(|_| ERR_OTHER)?;
        let mut response = BTreeMap::from([
            (
                Value::Integer(1),
                text_map([
                    ("id", Value::Bytes(c.id.clone())),
                    ("type", Value::Text("public-key".to_owned())),
                ]),
            ),
            (Value::Integer(2), Value::Bytes(auth_data)),
            (Value::Integer(3), Value::Bytes(signature.as_ref().to_vec())),
        ]);
        if c.discoverable {
            let mut user = vec![("id", Value::Bytes(c.user_id.clone()))];
            user.extend(c.user_name.clone().map(|n| ("name", Value::Text(n))));
            user.extend(
                c.user_display_name
                    .clone()
                    .map(|n| ("displayName", Value::Text(n))),
            );
            response.insert(Value::Integer(4), text_map(user));
        }
        if let Some(total) = total {
            response.insert(Value::Integer(5), Value::Integer(total as i128));
        }
        Ok(Value::Map(response))
    }
}

fn get_info() -> Value {
    int_map([
        (1, Value::Array(vec![Value::Text("FIDO_2_0".to_owned())])),
        (3, Value::Bytes(AAGUID.to_vec())),
        (
            4,
            text_map([
                ("rk", Value::Bool(true)),
                ("up", Value::Bool(true)),
                ("uv", Value::Bool(true)),
                ("plat", Value::Bool(false)),
            ]),
        ),
        (5, Value::Integer(1200)),
    ])
}

/// pinUvAuthParam. No PIN is ever set, so any token gets PIN_NOT_SET. For a
/// zero-length one, the platform's "touch to select" probe (CTAP 2.1 section
/// 6.1.2 step 1), PIN_NOT_SET also means "touched".
fn pin_auth(v: Option<&Value>) -> Result<(), u8> {
    match v {
        None => Ok(()),
        Some(_) => Err(ERR_PIN_NOT_SET),
    }
}

fn uv_flag(uv: bool) -> u8 {
    if uv { FLAG_UV } else { 0 }
}

fn auth_data(rp_id: &str, flags: u8, counter: u32) -> Vec<u8> {
    let mut data = digest(&SHA256, rp_id.as_bytes()).as_ref().to_vec();
    data.push(flags);
    data.extend(counter.to_be_bytes());
    data
}

/// COSE_Key for an uncompressed P-256 point, in CTAP canonical key order
/// (1, 3, -1, -2, -3).
fn cose_key(point: &[u8]) -> Vec<u8> {
    let (x, y) = point[1..].split_at(32);
    let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    key.extend(x);
    key.extend([0x22, 0x58, 0x20]);
    key.extend(y);
    key
}

fn get(p: &BTreeMap<Value, Value>, key: i128) -> Option<&Value> {
    p.get(&Value::Integer(key))
}

fn entry<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Map(m) => m.get(&Value::Text(key.to_owned())),
        _ => None,
    }
}

fn option(options: Option<&Value>, key: &str) -> Option<bool> {
    match options.and_then(|o| entry(o, key)) {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

fn credential_ids(v: Option<&Value>) -> Option<Vec<&[u8]>> {
    let Some(Value::Array(list)) = v else {
        return None;
    };
    let ids: Vec<&[u8]> = list
        .iter()
        .filter_map(|d| entry(d, "id").and_then(as_bytes))
        .collect();
    (!ids.is_empty()).then_some(ids)
}

fn as_bytes(v: &Value) -> Option<&[u8]> {
    match v {
        Value::Bytes(b) => Some(b),
        _ => None,
    }
}

fn as_text(v: &Value) -> Option<&str> {
    match v {
        Value::Text(s) => Some(s),
        _ => None,
    }
}

fn int_map<const N: usize>(entries: [(i128, Value); N]) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Integer(k), v))
            .collect(),
    )
}

fn text_map(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Text(k.to_owned()), v))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use libwebauthn::transport::{ChannelSettings, Device, hid::virtual_device};
    use ring::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
    use serde_cbor_2::Value;

    use super::*;

    const OK: u8 = 0x00;
    const ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
    const ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
    const ERR_NO_CREDENTIALS: u8 = 0x2e;
    const ERR_NOT_ALLOWED: u8 = 0x30;
    const ERR_PIN_NOT_SET: u8 = 0x35;
    const CID: u32 = 0x0102_0304;

    fn int(i: i128) -> Value {
        Value::Integer(i)
    }
    fn text(s: &str) -> Value {
        Value::Text(s.to_owned())
    }
    fn map<const N: usize>(entries: [(Value, Value); N]) -> Value {
        Value::Map(BTreeMap::from(entries))
    }
    fn field(v: &Value, k: Value) -> &Value {
        match v {
            Value::Map(m) => m.get(&k).expect("field present"),
            _ => panic!("not a map: {v:?}"),
        }
    }
    fn bytes(v: &Value) -> &[u8] {
        match v {
            Value::Bytes(b) => b,
            _ => panic!("not bytes: {v:?}"),
        }
    }

    /// Sends one authenticatorXxx CBOR command over CTAPHID; returns (status, body).
    fn ctap(a: &mut TestAuthenticator, cmd: u8, params: Option<Value>) -> (u8, Option<Value>) {
        let mut payload = vec![cmd];
        if let Some(p) = params {
            payload.extend(serde_cbor_2::to_vec(&p).unwrap());
        }
        a.send(&HidMessage::new(CID, HidCommand::Cbor, &payload));
        let reply = a.recv();
        assert!(matches!(reply.cmd, HidCommand::Cbor), "reply {reply:?}");
        assert_eq!(reply.cid, CID);
        let (&status, body) = reply.payload.split_first().expect("status byte");
        let body = (!body.is_empty()).then(|| serde_cbor_2::from_slice(body).unwrap());
        (status, body)
    }

    fn make_params(rp: &str, user: &[u8], rk: bool, exclude: Option<Vec<u8>>) -> Value {
        let mut m = BTreeMap::from([
            (int(1), Value::Bytes(vec![7; 32])),
            (int(2), map([(text("id"), text(rp))])),
            (
                int(3),
                map([
                    (text("id"), Value::Bytes(user.to_vec())),
                    (text("name"), text("alice")),
                ]),
            ),
            (
                int(4),
                Value::Array(vec![map([
                    (text("alg"), int(-7)),
                    (text("type"), text("public-key")),
                ])]),
            ),
            (int(7), map([(text("rk"), Value::Bool(rk))])),
        ]);
        if let Some(id) = exclude {
            m.insert(int(5), Value::Array(vec![descriptor(id)]));
        }
        Value::Map(m)
    }

    fn get_params(rp: &str, client_hash: &[u8], allow: Option<Vec<u8>>) -> Value {
        let mut m = BTreeMap::from([
            (int(1), text(rp)),
            (int(2), Value::Bytes(client_hash.to_vec())),
        ]);
        if let Some(id) = allow {
            m.insert(int(3), Value::Array(vec![descriptor(id)]));
        }
        Value::Map(m)
    }

    fn descriptor(id: Vec<u8>) -> Value {
        map([
            (text("id"), Value::Bytes(id)),
            (text("type"), text("public-key")),
        ])
    }

    /// Registers a credential; returns (credential id, uncompressed public key).
    fn register(a: &mut TestAuthenticator, rp: &str, user: &[u8], rk: bool) -> (Vec<u8>, Vec<u8>) {
        let (status, body) = ctap(a, 0x01, Some(make_params(rp, user, rk, None)));
        assert_eq!(status, OK);
        let body = body.unwrap();
        assert_eq!(field(&body, int(1)), &text("none"));
        let auth_data = bytes(field(&body, int(2)));
        let rp_hash = ring::digest::digest(&ring::digest::SHA256, rp.as_bytes());
        assert_eq!(&auth_data[..32], rp_hash.as_ref());
        assert_eq!(auth_data[32] & 0x41, 0x41, "UP and AT flags");
        let id_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        let cred_id = auth_data[55..55 + id_len].to_vec();
        let cose: Value = serde_cbor_2::from_slice(&auth_data[55 + id_len..]).unwrap();
        assert_eq!(field(&cose, int(3)), &int(-7));
        let mut public_key = vec![0x04];
        public_key.extend(bytes(field(&cose, int(-2))));
        public_key.extend(bytes(field(&cose, int(-3))));
        (cred_id, public_key)
    }

    #[test]
    fn init_assigns_a_channel_and_echoes_the_nonce() {
        let mut a = TestAuthenticator::default();
        let nonce = [1, 2, 3, 4, 5, 6, 7, 8];
        a.send(&HidMessage::broadcast(HidCommand::Init, &nonce));
        let reply = a.recv();
        assert!(matches!(reply.cmd, HidCommand::Init));
        assert_eq!(&reply.payload[..8], &nonce);
        let cid = u32::from_be_bytes(reply.payload[8..12].try_into().unwrap());
        assert_ne!(cid, 0);
        assert_ne!(cid, 0xffff_ffff);
        assert_eq!(reply.payload[16] & 0x04, 0x04, "CBOR capability");
    }

    #[test]
    fn get_info_advertises_fido2_with_resident_keys() {
        let (status, body) = ctap(&mut TestAuthenticator::default(), 0x04, None);
        assert_eq!(status, OK);
        let body = body.unwrap();
        assert_eq!(field(&body, int(1)), &Value::Array(vec![text("FIDO_2_0")]));
        assert_eq!(field(field(&body, int(4)), text("rk")), &Value::Bool(true));
    }

    #[test]
    fn register_then_sign_in_verifies_with_the_registered_key() {
        let mut a = TestAuthenticator::default();
        let (cred_id, public_key) = register(&mut a, "webauthn.io", b"user-1", false);

        let client_hash = [5u8; 32];
        let (status, body) = ctap(
            &mut a,
            0x02,
            Some(get_params(
                "webauthn.io",
                &client_hash,
                Some(cred_id.clone()),
            )),
        );
        assert_eq!(status, OK);
        let body = body.unwrap();
        assert_eq!(bytes(field(field(&body, int(1)), text("id"))), cred_id);
        let auth_data = bytes(field(&body, int(2)));
        assert_eq!(auth_data[32] & 0x01, 0x01, "UP flag");
        let counter = u32::from_be_bytes(auth_data[33..37].try_into().unwrap());
        assert!(counter > 0);
        let signed = [auth_data, &client_hash[..]].concat();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &public_key)
            .verify(&signed, bytes(field(&body, int(3))))
            .expect("signature verifies");
    }

    #[test]
    fn discoverable_credentials_are_found_without_an_allow_list() {
        let mut a = TestAuthenticator::default();
        let (first, _) = register(&mut a, "webauthn.io", b"user-1", true);
        let (second, _) = register(&mut a, "webauthn.io", b"user-2", true);
        register(&mut a, "webauthn.io", b"user-3", false);
        register(&mut a, "other.example", b"user-4", true);

        let (status, body) = ctap(
            &mut a,
            0x02,
            Some(get_params("webauthn.io", &[0; 32], None)),
        );
        assert_eq!(status, OK);
        let body = body.unwrap();
        assert_eq!(field(&body, int(5)), &int(2), "numberOfCredentials");
        let id1 = bytes(field(field(&body, int(1)), text("id"))).to_vec();
        assert_eq!(
            bytes(field(field(&body, int(4)), text("id"))).len(),
            6,
            "user handle"
        );

        let (status, body) = ctap(&mut a, 0x08, None);
        assert_eq!(status, OK);
        let id2 = bytes(field(field(&body.unwrap(), int(1)), text("id"))).to_vec();
        let mut got = [id1, id2];
        got.sort();
        let mut want = [first, second];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn unknown_and_excluded_credentials_are_refused() {
        let mut a = TestAuthenticator::default();
        let (status, _) = ctap(
            &mut a,
            0x02,
            Some(get_params("webauthn.io", &[0; 32], None)),
        );
        assert_eq!(status, ERR_NO_CREDENTIALS);

        let (cred_id, _) = register(&mut a, "webauthn.io", b"user-1", false);
        let (status, _) = ctap(
            &mut a,
            0x02,
            Some(get_params("other.example", &[0; 32], Some(cred_id.clone()))),
        );
        assert_eq!(status, ERR_NO_CREDENTIALS, "credential is bound to its RP");

        let (status, _) = ctap(
            &mut a,
            0x01,
            Some(make_params("webauthn.io", b"user-1", false, Some(cred_id))),
        );
        assert_eq!(status, ERR_CREDENTIAL_EXCLUDED);
    }

    #[test]
    fn only_es256_is_supported() {
        let mut params = make_params("webauthn.io", b"user-1", false, None);
        if let Value::Map(m) = &mut params {
            m.insert(int(4), Value::Array(vec![map([(text("alg"), int(-257))])]));
        }
        let (status, _) = ctap(&mut TestAuthenticator::default(), 0x01, Some(params));
        assert_eq!(status, ERR_UNSUPPORTED_ALGORITHM);
    }

    /// libwebauthn selects a USB key by sending a zero-length pinUvAuthParam and
    /// treating PIN_NOT_SET as "touched" (CTAP 2.1 section 6.1.2 step 1).
    #[test]
    fn empty_pin_auth_is_answered_as_a_touch() {
        let mut params = make_params(".dummy", &[1], false, None);
        if let Value::Map(m) = &mut params {
            m.insert(int(8), Value::Bytes(vec![]));
            m.insert(int(9), int(1));
        }
        let mut a = TestAuthenticator::default();
        let (status, _) = ctap(&mut a, 0x01, Some(params));
        assert_eq!(status, ERR_PIN_NOT_SET);
        let (status, _) = ctap(&mut a, 0x02, Some(get_params(".dummy", &[0; 32], None)));
        assert_eq!(status, ERR_NO_CREDENTIALS, "the probe stored nothing");
    }

    #[tokio::test]
    async fn libwebauthn_can_select_the_virtual_device() {
        let mut device = virtual_device(TestAuthenticator::default());
        let mut channel = device.channel(ChannelSettings::default()).await.unwrap();
        let selected = channel
            .blink_and_wait_for_user_presence(Duration::from_secs(5))
            .await
            .unwrap();
        assert!(selected);
    }

    #[test]
    fn only_offered_when_enabled_and_for_allowed_origins() {
        assert!(!origin_allowed("https://example.com"));
        assert!(!origin_allowed("https://webauthn.io.evil.example"));
        assert!(!origin_allowed("http://webauthn.io"));
        assert!(origin_allowed("https://webauthn.io"));
        assert!(origin_allowed("https://demo.yubico.com"));
        assert!(!offered(None, "https://webauthn.io"));
        assert!(!offered(Some("0".as_ref()), "https://webauthn.io"));
        assert!(!offered(Some("1".as_ref()), "https://example.com"));
        assert!(offered(Some("1".as_ref()), "https://webauthn.io"));
    }

    #[test]
    fn registering_again_for_the_same_user_replaces_the_discoverable_credential() {
        let mut a = TestAuthenticator::default();
        register(&mut a, "webauthn.io", b"user-1", true);
        let (newer, _) = register(&mut a, "webauthn.io", b"user-1", true);
        let (status, body) = ctap(
            &mut a,
            0x02,
            Some(get_params("webauthn.io", &[0; 32], None)),
        );
        assert_eq!(status, OK);
        let body = body.unwrap();
        assert_eq!(bytes(field(field(&body, int(1)), text("id"))), newer);
        assert!(
            matches!(&body, Value::Map(m) if !m.contains_key(&int(5))),
            "only one left"
        );
    }

    #[test]
    fn next_assertions_end_and_are_dropped_by_other_commands() {
        let mut a = TestAuthenticator::default();
        for user in [b"user-1", b"user-2"] {
            register(&mut a, "webauthn.io", user, true);
        }
        let get = || Some(get_params("webauthn.io", &[0; 32], None));
        assert_eq!(ctap(&mut a, 0x02, get()).0, OK);
        assert_eq!(ctap(&mut a, 0x08, None).0, OK);
        assert_eq!(
            ctap(&mut a, 0x08, None).0,
            ERR_NOT_ALLOWED,
            "list exhausted"
        );

        assert_eq!(ctap(&mut a, 0x02, get()).0, OK);
        assert_eq!(ctap(&mut a, 0x04, None).0, OK);
        assert_eq!(
            ctap(&mut a, 0x08, None).0,
            ERR_NOT_ALLOWED,
            "dropped by getInfo"
        );
    }

    #[test]
    fn silent_assertions_do_not_claim_user_presence() {
        let mut a = TestAuthenticator::default();
        let (cred_id, _) = register(&mut a, "webauthn.io", b"user-1", false);
        let mut params = get_params("webauthn.io", &[0; 32], Some(cred_id));
        if let Value::Map(m) = &mut params {
            m.insert(int(5), map([(text("up"), Value::Bool(false))]));
        }
        let (status, body) = ctap(&mut a, 0x02, Some(params));
        assert_eq!(status, OK);
        assert_eq!(
            bytes(field(&body.unwrap(), int(2)))[32] & 0x05,
            0,
            "no UP or UV"
        );
    }

    #[test]
    fn pin_tokens_are_refused_because_no_pin_is_set() {
        let mut params = make_params("webauthn.io", b"user-1", false, None);
        if let Value::Map(m) = &mut params {
            m.insert(int(8), Value::Bytes(vec![1; 16]));
            m.insert(int(9), int(1));
        }
        let (status, _) = ctap(&mut TestAuthenticator::default(), 0x01, Some(params));
        assert_eq!(status, ERR_PIN_NOT_SET);
    }

    #[test]
    fn channel_ids_skip_reserved_values() {
        let mut a = TestAuthenticator {
            last_cid: BROADCAST_CID - 1,
            ..Default::default()
        };
        for _ in 0..2 {
            a.send(&HidMessage::broadcast(HidCommand::Init, &[0; 8]));
            let reply = a.recv();
            let cid = u32::from_be_bytes(reply.payload[8..12].try_into().unwrap());
            assert!(cid != 0 && cid != BROADCAST_CID, "cid {cid:#x}");
        }
    }
}
