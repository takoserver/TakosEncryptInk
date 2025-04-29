use crate::r#type::{ShareKey, ShareSignKey, EncryptedData, Sign};
use crate::keyutils::{generate_kem_key_pair, generate_dsa65_key_pair};
use crate::crypto::{encrypt, decrypt};
use crate::master_key::{is_valid_master_key_private, sign_master_key};
use crate::core::is_valid_uuid_v7;
use crate::utils::key_hash;
use crate::signature::verify_with_mlds65;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::Utc;
use serde_json;

/// ShareKey生成
pub fn generate_share_key(master_priv: &str, session_uuid: &str) -> Option<(String,String,String)> {
    if !is_valid_master_key_private(master_priv) || !is_valid_uuid_v7(session_uuid) { return None }
    let (pub_b64, priv_b64) = generate_kem_key_pair().ok()?;
    let ts = Utc::now().timestamp_millis() as u64;
    let pk = ShareKey{ key_type:"shareKeyPublic".into(), key:pub_b64.clone(), algorithm:"ML-KEM-768".into(), timestamp:ts, session_uuid:session_uuid.into() };
    let sk = ShareKey{ key_type:"shareKeyPrivate".into(), key:priv_b64.clone(), algorithm:"ML-KEM-768".into(), timestamp:ts, session_uuid:session_uuid.into() };
    let pkj = serde_json::to_string(&pk).ok()?;
    let skj = serde_json::to_string(&sk).ok()?;
    let mh = key_hash(master_priv);
    let sign = sign_master_key(master_priv, &pkj, &mh)?;
    Some((pkj,skj,sign))
}
pub fn is_valid_share_key_public(json: &str)->bool {
    serde_json::from_str::<ShareKey>(json).map(|k| k.key_type=="shareKeyPublic" && BASE64.decode(&k.key).map_or(false,|b|b.len()==1184)).unwrap_or(false)
}
pub fn is_valid_share_key_private(json: &str)->bool {
    serde_json::from_str::<ShareKey>(json).map(|k| k.key_type=="shareKeyPrivate"&&BASE64.decode(&k.key).map_or(false,|b|b.len()==2400)).unwrap_or(false)
}
pub fn encrypt_data_share_key(pub_json: &str, data: &str) -> Option<String> {
    let sk = serde_json::from_str::<ShareKey>(pub_json).ok()?;
    if sk.key_type != "shareKeyPublic" { return None; }
    let enc = encrypt(data, &sk.key);
    let ed = EncryptedData {
        key_type: "shareKey".into(),
        key_hash: key_hash(pub_json),
        encrypted_data: enc.encrypted_data,
        iv: enc.iv,
        algorithm: Some(enc.algorithm),
        cipher_text: Some(enc.cipher_text),
    };
    serde_json::to_string(&ed).ok()
}

pub fn decrypt_data_share_key(priv_json: &str, json: &str) -> Option<String> {
    let sk = serde_json::from_str::<ShareKey>(priv_json).ok()?;
    if sk.key_type != "shareKeyPrivate" { return None; }
    let ed: EncryptedData = serde_json::from_str(json).ok()?;
    let ciphertext = ed.cipher_text.as_ref()?;
    Some(decrypt(&ed.encrypted_data, ciphertext, &ed.iv, &sk.key))
}

pub fn is_valid_encrypted_data_share_key(json:&str)->bool {
    serde_json::from_str::<EncryptedData>(json).map(|ed|ed.key_type=="shareKey").unwrap_or(false)
}

/// ShareSignKey生成／検証
pub fn generate_share_sign_key(master_priv:&str, session_uuid:&str)->Option<(String,String,String)> {
    if !is_valid_master_key_private(master_priv) || !is_valid_uuid_v7(session_uuid) { return None }
    let (pub_b64, priv_b64) = generate_dsa65_key_pair().ok()?;
    let ts = Utc::now().timestamp_millis() as u64;
    let pk = ShareSignKey{ key_type:"shareSignKeyPublic".into(), key:pub_b64.clone(), algorithm:"ML-DSA-65".into(), timestamp:ts, session_uuid:session_uuid.into() };
    let sk = ShareSignKey{ key_type:"shareSignKeyPrivate".into(), key:priv_b64.clone(), algorithm:"ML-DSA-65".into(), timestamp:ts, session_uuid:session_uuid.into() };
    let pkj=serde_json::to_string(&pk).ok()?;
    let skj=serde_json::to_string(&sk).ok()?;
    let mh = key_hash(master_priv);
    let sign = sign_master_key(master_priv, &pkj, &mh)?;
    Some((pkj,skj,sign))
}
pub fn is_valid_share_sign_key_public(json:&str)->bool {
    serde_json::from_str::<ShareSignKey>(json).map(|k| k.key_type=="shareSignKeyPublic").unwrap_or(false)
}
pub fn is_valid_share_sign_key_private(json:&str)->bool {
    serde_json::from_str::<ShareSignKey>(json).map(|k| k.key_type=="shareSignKeyPrivate").unwrap_or(false)
}
pub fn sign_data_share_sign_key(priv_json:&str, data:&str, key_hash:&str)->Option<String> {
    let sk: ShareSignKey = serde_json::from_str(priv_json).ok()?;
    if sk.key_type != "shareSignKeyPrivate" { return None; }
    crate::signature::create_signature_object_mlds65(&sk.key, data.as_bytes(), key_hash, "shareSignKey").ok()
}
pub fn verify_data_share_sign_key(pub_json: &str, sign_json: &str, data: &str) -> bool {
    let sk = match serde_json::from_str::<ShareSignKey>(pub_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = match serde_json::from_str::<Sign>(sign_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if sig.key_type != "shareSignKey" { return false; }
    verify_with_mlds65(&sk.key, data.as_bytes(), &sig.signature)
}
pub fn is_valid_sign_share_sign_key(json:&str)->bool {
    serde_json::from_str::<Sign>(json).map(|s|s.key_type=="shareSignKey").unwrap_or(false)
}
