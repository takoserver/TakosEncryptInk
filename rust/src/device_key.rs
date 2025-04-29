use crate::r#type::{DeviceKey, EncryptedData};
use crate::keyutils::generate_symmetric_key;
use crate::crypto::{encrypt_with_symmetric_key, decrypt_with_symmetric_key};
use crate::utils::key_hash;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json;

/// デバイス鍵生成
pub fn generate_device_key() -> String {
    let k = generate_symmetric_key();
    let dk = DeviceKey{ key_type:"deviceKey".into(), key:k.clone() };
    serde_json::to_string(&dk).unwrap()
}
pub fn is_valid_device_key(json:&str)->bool {
    serde_json::from_str::<DeviceKey>(json)
        .map(|d| BASE64.decode(&d.key).map_or(false,|b|b.len()==32))
        .unwrap_or(false)
}
pub fn encrypt_data_device_key(json:&str,data:&str)->Option<String> {
    let dk:DeviceKey=serde_json::from_str(json).ok()?;
    if dk.key_type!="deviceKey" {return None}
    let enc = encrypt_with_symmetric_key(data, &dk.key);
    let ed=EncryptedData{ key_type:"deviceKey".into(), key_hash:key_hash(json), encrypted_data:enc.encrypted_data, iv:enc.iv, algorithm:Some(enc.algorithm), cipher_text:None };
    serde_json::to_string(&ed).ok()
}
pub fn decrypt_data_device_key(json:&str,enc_json:&str)->Option<String> {
    let dk:DeviceKey=serde_json::from_str(json).ok()?;
    let ed:EncryptedData=serde_json::from_str(enc_json).ok()?;
    Some(decrypt_with_symmetric_key(&ed.encrypted_data, &ed.iv, &dk.key))
}
pub fn is_valid_encrypted_data_device_key(json:&str)->bool {
    serde_json::from_str::<EncryptedData>(json).map(|ed|ed.key_type=="deviceKey").unwrap_or(false)
}
