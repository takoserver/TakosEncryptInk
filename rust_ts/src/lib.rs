use wasm_bindgen::prelude::*;
use wasm_bindgen::JsValue;
use takos_encrypt_ink_rs as core;
use console_error_panic_hook;
use serde_json::json;

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub fn key_hash(input: &str) -> String {
    core::key_hash(input)
}

#[wasm_bindgen]
pub fn is_valid_uuid_v7(input: &str) -> bool {
    core::is_valid_uuid_v7(input)
}

// ---- 非対称暗号化・復号 ----
#[wasm_bindgen]
pub fn encrypt(data: &str, public_key: &str) -> JsValue {
    JsValue::from_serde(&core::encrypt(data, public_key)).unwrap()
}
#[wasm_bindgen]
pub fn decrypt(encrypted_data: &str, cipher_text: &str, iv: &str, private_key: &str) -> String {
    core::decrypt(encrypted_data, cipher_text, iv, private_key)
}

// ---- 対称暗号化・復号 ----
#[wasm_bindgen]
pub fn encrypt_with_symmetric_key(data: &str, key: &str) -> JsValue {
    JsValue::from_serde(&core::encrypt_with_symmetric_key(data, key)).unwrap()
}
#[wasm_bindgen]
pub fn decrypt_with_symmetric_key(encrypted_data: &str, iv: &str, key: &str) -> String {
    core::decrypt_with_symmetric_key(encrypted_data, iv, key)
}

// ---- keyutils ----
#[wasm_bindgen] pub fn generate_kem_key_pair() -> JsValue { JsValue::from_serde(&core::generate_kem_key_pair().unwrap()).unwrap() }
#[wasm_bindgen] pub fn generate_dsa65_key_pair() -> JsValue { JsValue::from_serde(&core::generate_dsa65_key_pair().unwrap()).unwrap() }
#[wasm_bindgen] pub fn generate_dsa87_key_pair() -> JsValue { JsValue::from_serde(&core::generate_dsa87_key_pair().unwrap()).unwrap() }
#[wasm_bindgen] pub fn generate_symmetric_key() -> String { core::generate_symmetric_key() }
#[wasm_bindgen] pub fn is_valid_key_pair_sign(pub_json: &str, priv_json: &str) -> bool { core::is_valid_key_pair_sign(pub_json, priv_json) }
#[wasm_bindgen] pub fn is_valid_key_pair_encrypt(pub_json: &str, priv_json: &str) -> bool { core::is_valid_key_pair_encrypt(pub_json, priv_json) }
#[wasm_bindgen] pub fn is_valid_dsa65_key(key: &str, is_pub: bool) -> bool { core::is_valid_dsa65_key(key, is_pub) }
#[wasm_bindgen] pub fn is_valid_dsa87_key(key: &str, is_pub: bool) -> bool { core::is_valid_dsa87_key(key, is_pub) }
#[wasm_bindgen] pub fn is_valid_kem_key(key: &str, is_pub: bool) -> bool { core::is_valid_kem_key(key, is_pub) }
#[wasm_bindgen] pub fn is_valid_symmetric_key(key: &str) -> bool { core::is_valid_symmetric_key(key) }
#[wasm_bindgen] pub fn generate_random_string(len: usize) -> String { core::generate_random_string(len) }

// ---- MasterKey ----
#[wasm_bindgen] pub fn generate_master_key() -> JsValue { JsValue::from_serde(&core::generate_master_key()).unwrap() }
#[wasm_bindgen] pub fn sign_master_key(key_json: &str, data: &str, hash: &str) -> Option<String> { core::sign_master_key(key_json, data, hash) }
#[wasm_bindgen] pub fn verify_master_key(key: &str, sign: &str, data: &str) -> bool { core::verify_master_key(key, sign, data) }
#[wasm_bindgen] pub fn is_valid_master_key_private(key_json: &str) -> bool { core::is_valid_master_key_private(key_json) }
#[wasm_bindgen] pub fn is_valid_master_key_public(key_json: &str) -> bool { core::is_valid_master_key_public(key_json) }
#[wasm_bindgen] pub fn is_valid_sign_master_key(sign_json: &str) -> bool { core::is_valid_sign_master_key(sign_json) }

// ---- IdentityKey ----
#[wasm_bindgen]
pub fn sign_identity_key(key_json: &str, data: &str, hash: &str) -> Option<String> { core::sign_identity_key(key_json, data, hash) }
#[wasm_bindgen]
pub fn verify_identity_key(key_json: &str, sign: &str, data: &str) -> bool { core::verify_identity_key(key_json, sign, data) }
#[wasm_bindgen]
pub fn generate_identity_key(uuid: &str, pubk: &str, privk: &str) -> JsValue {
    match core::generate_identity_key(uuid, pubk, privk) {
        Some((pk, sk, sign)) => {
            JsValue::from_serde(&json!({
                "publicKey": pk,
                "privateKey": sk,
                "sign": sign
            })).unwrap()
        }
        None => JsValue::NULL,
    }
}
#[wasm_bindgen] pub fn is_valid_identity_key_private(key_json: &str) -> bool { core::is_valid_identity_key_private(key_json) }
#[wasm_bindgen] pub fn is_valid_identity_key_public(key_json: &str) -> bool { core::is_valid_identity_key_public(key_json) }
#[wasm_bindgen] pub fn is_valid_sign_identity_key(sign_json: &str) -> bool { core::is_valid_sign_identity_key(sign_json) }

// ---- AccountKey ----
#[wasm_bindgen]
pub fn generate_account_key(pubk: &str, privk: &str) -> JsValue {
    match core::generate_account_key(pubk, privk) {
        Some((pk, sk, sign)) => {
            JsValue::from_serde(&json!({
                "publicKey": pk,
                "privateKey": sk,
                "sign": sign
            })).unwrap()
        }
        None => JsValue::NULL,
    }
}
#[wasm_bindgen] pub fn is_valid_account_key_public(json: &str) -> bool { core::is_valid_account_key_public(json) }
#[wasm_bindgen] pub fn is_valid_account_key_private(json: &str) -> bool { core::is_valid_account_key_private(json) }
#[wasm_bindgen] pub fn encrypt_data_account_key(key_json: &str, data: &str) -> Option<String> { core::encrypt_data_account_key(key_json, data) }
#[wasm_bindgen] pub fn is_valid_encrypted_data_account_key(json: &str) -> bool { core::is_valid_encrypted_data_account_key(json) }
#[wasm_bindgen] pub fn decrypt_data_account_key(key_json: &str, enc_json: &str) -> Option<String> { core::decrypt_data_account_key(key_json, enc_json) }
#[wasm_bindgen] pub fn is_valid_encrypted_account_key(json: &str) -> bool { core::is_valid_encrypted_account_key(json) }

// ---- ServerKey ----
#[wasm_bindgen]
pub fn generate_server_key() -> JsValue {
    // core::generate_server_key は (pub_json, priv_json) を返す
    let (pub_json, priv_json) = core::generate_server_key();
    JsValue::from_serde(&json!({
        "publicKey": pub_json,
        "privateKey": priv_json
    })).unwrap()
}
#[wasm_bindgen] pub fn is_valid_server_key_public(json: &str) -> bool { core::is_valid_server_key_public(json) }
#[wasm_bindgen] pub fn is_valid_server_key_private(json: &str) -> bool { core::is_valid_server_key_private(json) }
#[wasm_bindgen] pub fn sign_data_server_key(priv_json: &str, data: &str, hash: &str) -> Option<String> { core::sign_data_server_key(priv_json, data, hash) }
#[wasm_bindgen] pub fn verify_data_server_key(pub_json: &str, sign: &str, data: &str) -> bool { core::verify_data_server_key(pub_json, sign, data) }

// ---- RoomKey ----
#[wasm_bindgen] pub fn generate_room_key(uuid: &str) -> Option<String> { core::generate_room_key(uuid) }
#[wasm_bindgen] pub fn is_valid_room_key(json: &str) -> bool { core::is_valid_room_key(json) }
#[wasm_bindgen] pub fn encrypt_data_room_key(json: &str, data: &str) -> Option<String> { core::encrypt_data_room_key(json, data) }
#[wasm_bindgen] pub fn decrypt_data_room_key(json: &str, enc_json: &str) -> Option<String> { core::decrypt_data_room_key(json, enc_json) }
#[wasm_bindgen] pub fn is_valid_encrypted_data_room_key(json: &str) -> bool { core::is_valid_encrypted_data_room_key(json) }

// ---- ShareKey / ShareSignKey ----
#[wasm_bindgen]
pub fn generate_share_key(privk: &str, uuid: &str) -> JsValue {
    match core::generate_share_key(privk, uuid) {
        Some((pk, sk, sign)) => JsValue::from_serde(&json!({
            "publicKey": pk,
            "privateKey": sk,
            "sign": sign
        })).unwrap(),
        None => JsValue::NULL,
    }
}
#[wasm_bindgen]
pub fn generate_share_sign_key(privk: &str, uuid: &str) -> JsValue {
    match core::generate_share_sign_key(privk, uuid) {
        Some((pk, sk, sign)) => JsValue::from_serde(&json!({
            "publicKey": pk,
            "privateKey": sk,
            "sign": sign
        })).unwrap(),
        None => JsValue::NULL,
    }
}
#[wasm_bindgen] pub fn is_valid_share_key_public(json: &str) -> bool { core::is_valid_share_key_public(json) }
#[wasm_bindgen] pub fn is_valid_share_key_private(json: &str) -> bool { core::is_valid_share_key_private(json) }
#[wasm_bindgen] pub fn encrypt_data_share_key(pub_json: &str, data: &str) -> Option<String> { core::encrypt_data_share_key(pub_json, data) }
#[wasm_bindgen] pub fn decrypt_data_share_key(priv_json: &str, json: &str) -> Option<String> { core::decrypt_data_share_key(priv_json, json) }
#[wasm_bindgen] pub fn is_valid_encrypted_data_share_key(json: &str) -> bool { core::is_valid_encrypted_data_share_key(json) }
#[wasm_bindgen] pub fn is_valid_share_sign_key_public(json: &str) -> bool { core::is_valid_share_sign_key_public(json) }
#[wasm_bindgen] pub fn is_valid_share_sign_key_private(json: &str) -> bool { core::is_valid_share_sign_key_private(json) }
#[wasm_bindgen] pub fn sign_data_share_sign_key(priv_json: &str, data: &str, hash: &str) -> Option<String> { core::sign_data_share_sign_key(priv_json, data, hash) }
#[wasm_bindgen] pub fn verify_data_share_sign_key(pub_json: &str, sign: &str, data: &str) -> bool { core::verify_data_share_sign_key(pub_json, sign, data) }
#[wasm_bindgen] pub fn is_valid_sign_share_sign_key(json: &str) -> bool { core::is_valid_sign_share_sign_key(json) }

// ---- MigrateKey / MigrateSignKey ----
#[wasm_bindgen]
pub fn generate_migrate_key() -> JsValue {
    let (pk, sk) = core::generate_migrate_key();
    JsValue::from_serde(&json!({
        "publicKey": pk,
        "privateKey": sk
    })).unwrap()
}
#[wasm_bindgen]
pub fn generate_migrate_sign_key() -> JsValue {
    let (pk, sk) = core::generate_migrate_sign_key();
    JsValue::from_serde(&json!({
        "publicKey": pk,
        "privateKey": sk
    })).unwrap()
}
#[wasm_bindgen] pub fn is_valid_migrate_key_public(json: &str) -> bool { core::is_valid_migrate_key_public(json) }
#[wasm_bindgen] pub fn is_valid_migrate_key_private(json: &str) -> bool { core::is_valid_migrate_key_private(json) }
#[wasm_bindgen] pub fn encrypt_data_migrate_key(pub_json: &str, data: &str) -> Option<String> { core::encrypt_data_migrate_key(pub_json, data) }
#[wasm_bindgen] pub fn decrypt_data_migrate_key(priv_json: &str, enc_json: &str) -> Option<String> { core::decrypt_data_migrate_key(priv_json, enc_json) }
#[wasm_bindgen] pub fn is_valid_encrypted_data_migrate_key(json: &str) -> bool { core::is_valid_encrypted_data_migrate_key(json) }
#[wasm_bindgen] pub fn sign_data_migrate_sign_key(priv_json: &str, data: &str, hash: &str) -> Option<String> { core::sign_data_migrate_sign_key(priv_json, data, hash) }
#[wasm_bindgen] pub fn verify_data_migrate_sign_key(pub_json: &str, sign: &str, data: &str) -> bool { core::verify_data_migrate_sign_key(pub_json, sign, data) }
#[wasm_bindgen] pub fn is_valid_sign_migrate_sign_key(json: &str) -> bool { core::is_valid_sign_migrate_sign_key(json) }

// ---- DeviceKey ----
#[wasm_bindgen] pub fn generate_device_key() -> String { core::generate_device_key() }
#[wasm_bindgen] pub fn is_valid_device_key(json: &str) -> bool { core::is_valid_device_key(json) }
#[wasm_bindgen] pub fn encrypt_data_device_key(json: &str, data: &str) -> Option<String> { core::encrypt_data_device_key(json, data) }
#[wasm_bindgen] pub fn decrypt_data_device_key(json: &str, enc_json: &str) -> Option<String> { core::decrypt_data_device_key(json, enc_json) }
#[wasm_bindgen] pub fn is_valid_encrypted_data_device_key(json: &str) -> bool { core::is_valid_encrypted_data_device_key(json) }

// ---- Message ----
#[wasm_bindgen]
pub fn encrypt_message(message: &str, metadata: &str, room_key: &str, identity_priv: &str, identity_pubhash: &str, roomid: &str) -> Option<String> {
    core::encrypt_message(message, metadata, room_key, identity_priv, identity_pubhash, roomid)
}
#[wasm_bindgen]
pub fn decrypt_message(message: &str, sign: &str, server_timestamp: u64, room_key: &str, identity_pub: &str, roomid: &str) -> Option<String> {
    core::decrypt_message(message, sign, server_timestamp, room_key, identity_pub, roomid)
}
#[wasm_bindgen] pub fn is_valid_message(message: &str) -> bool { core::is_valid_message(message) }
#[wasm_bindgen]
pub fn create_text_content(
    text: &str,
    format: Option<String>,
    is_thumbnail: Option<bool>,
    thumbnail_of: Option<String>,
    original_size: Option<u64>,
) -> Option<String> {
    core::create_text_content(
        text,
        format.as_deref(),
        is_thumbnail,
        thumbnail_of.as_deref(),
        original_size,
    )
}
#[wasm_bindgen]
pub fn create_image_content(
    uri: &str,
    filename: &str,
    mime_type: &str,
    is_thumbnail: Option<bool>,
    thumbnail_of: Option<String>,
    original_size: Option<u64>,
) -> Option<String> {
    core::create_image_content(
        uri,
        filename,
        mime_type,
        is_thumbnail,
        thumbnail_of.as_deref(),
        original_size,
    )
}
#[wasm_bindgen]
pub fn create_video_content(
    uri: &str,
    filename: &str,
    mime_type: &str,
    is_thumbnail: Option<bool>,
    thumbnail_of: Option<String>,
    original_size: Option<u64>,
) -> Option<String> {
    core::create_video_content(
        uri,
        filename,
        mime_type,
        is_thumbnail,
        thumbnail_of.as_deref(),
        original_size,
    )
}
#[wasm_bindgen]
pub fn create_audio_content(
    uri: &str,
    filename: &str,
    mime_type: &str,
    is_thumbnail: Option<bool>,
    thumbnail_of: Option<String>,
    original_size: Option<u64>,
) -> Option<String> {
    core::create_audio_content(
        uri,
        filename,
        mime_type,
        is_thumbnail,
        thumbnail_of.as_deref(),
        original_size,
    )
}
#[wasm_bindgen]
pub fn create_file_content(
    uri: &str,
    filename: &str,
    mime_type: &str,
    is_thumbnail: Option<bool>,
    thumbnail_of: Option<String>,
    original_size: Option<u64>,
) -> Option<String> {
    core::create_file_content(
        uri,
        filename,
        mime_type,
        is_thumbnail,
        thumbnail_of.as_deref(),
        original_size,
    )
}
#[wasm_bindgen] pub fn encrypt_room_key_with_account_keys(users_json: &str, room_key_json: &str) -> Option<String> { core::encrypt_room_key_with_account_keys(users_json, room_key_json) }
