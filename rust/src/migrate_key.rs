use crate::r#type::{MigrateKey, MigrateSignKey, EncryptedData, Sign};
use crate::keyutils::{generate_kem_key_pair, generate_dsa65_key_pair};
use crate::crypto::{encrypt, decrypt};
use crate::utils::key_hash;
use crate::signature::{create_signature_object_mlds65, verify_with_mlds65};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json;

/// MigrateKey 生成
pub fn generate_migrate_key() -> (String,String) {
    let (pub_b64, priv_b64)=generate_kem_key_pair().unwrap();
    let pk=MigrateKey{key_type:"migrateKeyPublic".into(),key:pub_b64, timestamp:None};
    let sk=MigrateKey{key_type:"migrateKeyPrivate".into(),key:priv_b64,timestamp:None};
    (serde_json::to_string(&pk).unwrap(),serde_json::to_string(&sk).unwrap())
}
pub fn is_valid_migrate_key_public(json:&str)->bool {
    serde_json::from_str::<MigrateKey>(json).map(|k|k.key_type=="migrateKeyPublic"&&BASE64.decode(&k.key).map_or(false,|b|b.len()==1184)).unwrap_or(false)
}
pub fn is_valid_migrate_key_private(json:&str)->bool {
    serde_json::from_str::<MigrateKey>(json).map(|k|k.key_type=="migrateKeyPrivate"&&BASE64.decode(&k.key).map_or(false,|b|b.len()==2400)).unwrap_or(false)
}
pub fn encrypt_data_migrate_key(pub_json:&str, data:&str)->Option<String> {
    let mk: MigrateKey = match serde_json::from_str(pub_json) { Ok(v) => v, Err(_) => return None };
    if mk.key_type!="migrateKeyPublic" {return None}
    let enc = encrypt(data, &mk.key);
    let ed=EncryptedData{ key_type:"migrateKey".into(), key_hash:key_hash(pub_json), encrypted_data:enc.encrypted_data, iv:enc.iv, algorithm:Some(enc.algorithm), cipher_text:Some(enc.cipher_text) };
    serde_json::to_string(&ed).ok()
}
pub fn decrypt_data_migrate_key(priv_json:&str, json:&str)->Option<String> {
    let mk: MigrateKey=serde_json::from_str(priv_json).ok()?;
    if mk.key_type!="migrateKeyPrivate"{return None}
    let ed:EncryptedData=serde_json::from_str(json).ok()?;
    let ciphertext = ed.cipher_text.as_ref()?;
    Some(decrypt(&ed.encrypted_data, ciphertext, &ed.iv, &mk.key))
}
pub fn is_valid_encrypted_data_migrate_key(json:&str)->bool {
    serde_json::from_str::<EncryptedData>(json).map(|ed|ed.key_type=="migrateKey").unwrap_or(false)
}

/// MigrateSignKey 生成／署名／検証
pub fn generate_migrate_sign_key()->(String,String) {
    let (pub_b64, priv_b64)=generate_dsa65_key_pair().unwrap();
    let pk=MigrateSignKey{key_type:"migrateSignKeyPublic".into(),key:pub_b64,timestamp:None};
    let sk=MigrateSignKey{key_type:"migrateSignKeyPrivate".into(),key:priv_b64,timestamp:None};
    (serde_json::to_string(&pk).unwrap(),serde_json::to_string(&sk).unwrap())
}
pub fn sign_data_migrate_sign_key(priv_json:&str, data:&str, key_hash:&str)->Option<String> {
    let sk:MigrateSignKey=serde_json::from_str(priv_json).ok()?;
    if sk.key_type!="migrateSignKeyPrivate"{return None}
    create_signature_object_mlds65(&sk.key,data.as_bytes(),key_hash,"migrateSignKey").ok()
}
pub fn verify_data_migrate_sign_key(pub_json:&str, sign_json:&str, data:&str)->bool {
    let pk = match serde_json::from_str::<MigrateSignKey>(pub_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let s = match serde_json::from_str::<Sign>(sign_json) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if s.key_type != "migrateSignKey" { return false; }
    verify_with_mlds65(&pk.key, data.as_bytes(), &s.signature)
}
pub fn is_valid_sign_migrate_sign_key(json:&str)->bool {
    serde_json::from_str::<Sign>(json).map(|s|s.key_type=="migrateSignKey").unwrap_or(false)
}
