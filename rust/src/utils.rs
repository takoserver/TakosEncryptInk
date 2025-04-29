use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

/// 入力文字列の SHA-256 ハッシュを Base64 文字列で返す
pub fn key_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    BASE64.encode(result)
}
