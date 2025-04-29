
// モジュール公開
pub mod utils;
pub mod core;
pub mod crypto;
pub mod r#type;
pub mod signature;
pub mod keyutils;
pub mod master_key;
pub mod identity_key;
pub mod account_key;
pub mod server_key;
pub mod room_key;
pub mod share_key;
pub mod migrate_key;
pub mod device_key;
pub mod schema;
pub mod message;


// 外部公開用 re-export
pub use utils::key_hash;
pub use core::is_valid_uuid_v7;
pub use crypto::{
    AsymmetricEncrypted,
    SymmetricEncrypted,
    encrypt,
    decrypt,
    encrypt_with_symmetric_key,
    decrypt_with_symmetric_key,
};
pub use r#type::*;
pub use signature::{
    sign_with_mlds87,
    verify_with_mlds87,
    sign_with_mlds65,
    verify_with_mlds65,
    create_signature_object_mlds87,
    create_signature_object_mlds65,
    verify_signature_object,
};
pub use keyutils::{
    generate_kem_key_pair,
    generate_dsa65_key_pair,
    generate_dsa87_key_pair,
    generate_symmetric_key,
    is_valid_key_pair_sign,
    is_valid_key_pair_encrypt,
    is_valid_dsa65_key,
    is_valid_dsa87_key,
    is_valid_kem_key,
    is_valid_symmetric_key,
    generate_random_string,
};
pub use master_key::{
    generate_master_key,
    sign_master_key,
    verify_master_key,
    is_valid_master_key_private,
    is_valid_master_key_public,
    is_valid_sign_master_key,
};
pub use identity_key::{
    sign_identity_key,
    verify_identity_key,
    generate_identity_key,
    is_valid_identity_key_private,
    is_valid_identity_key_public,
    is_valid_sign_identity_key,
};
pub use account_key::{
    generate_account_key,
    is_valid_account_key_public,
    is_valid_account_key_private,
    encrypt_data_account_key,
    is_valid_encrypted_data_account_key,
    decrypt_data_account_key,
    is_valid_encrypted_account_key,
};
pub use server_key::{
    generate_server_key,
    is_valid_server_key_public,
    is_valid_server_key_private,
    sign_data_server_key,
    verify_data_server_key,
};
pub use room_key::{
    generate_room_key,
    is_valid_room_key,
    encrypt_data_room_key,
    decrypt_data_room_key,
    is_valid_encrypted_data_room_key,
};
pub use share_key::{
    generate_share_key,
    is_valid_share_key_public,
    is_valid_share_key_private,
    encrypt_data_share_key,
    decrypt_data_share_key,
    is_valid_encrypted_data_share_key,
    generate_share_sign_key,
    is_valid_share_sign_key_public,
    is_valid_share_sign_key_private,
    sign_data_share_sign_key,
    verify_data_share_sign_key,
    is_valid_sign_share_sign_key,
};
pub use migrate_key::{
    generate_migrate_key,
    is_valid_migrate_key_public,
    is_valid_migrate_key_private,
    encrypt_data_migrate_key,
    decrypt_data_migrate_key,
    is_valid_encrypted_data_migrate_key,
    generate_migrate_sign_key,
    sign_data_migrate_sign_key,
    verify_data_migrate_sign_key,
    is_valid_sign_migrate_sign_key,
};
pub use device_key::{
    generate_device_key,
    is_valid_device_key,
    encrypt_data_device_key,
    decrypt_data_device_key,
    is_valid_encrypted_data_device_key,
};
pub use message::{
    encrypt_message,
    decrypt_message,
    is_valid_message,
    create_text_content,
    create_image_content,
    create_video_content,
    create_audio_content,
    create_file_content,
    encrypt_room_key_with_account_keys,
};