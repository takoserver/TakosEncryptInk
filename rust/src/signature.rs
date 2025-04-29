use crate::r#type::Sign;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ml_dsa::{
    EncodedSigningKey, EncodedVerifyingKey, EncodedSignature,
    MlDsa65, MlDsa87,
    SigningKey, VerifyingKey, Signature
};
use ml_dsa::signature::{Signer, Verifier, SignatureEncoding};
use serde_json;

/// ML‑DSA‑87 署名 (Base64 出力)
pub fn sign_with_mlds87(private_key_b64: &str, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let sk_bytes = BASE64.decode(private_key_b64)?;
    let sk_arr = <EncodedSigningKey<MlDsa87>>::try_from(&sk_bytes[..])?;
    let sk = SigningKey::<MlDsa87>::decode(&sk_arr);
    let sig: Signature<MlDsa87> = sk.sign(data);
    Ok(BASE64.encode(sig.to_bytes()))
}

/// ML‑DSA‑87 検証
pub fn verify_with_mlds87(public_key_b64: &str, data: &[u8], signature_b64: &str) -> bool {
    let pk_bytes = match BASE64.decode(public_key_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk_arr = match <EncodedVerifyingKey<MlDsa87>>::try_from(&pk_bytes[..]) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pk = VerifyingKey::<MlDsa87>::decode(&pk_arr);
    let sig_bytes = match BASE64.decode(signature_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_arr = match <EncodedSignature<MlDsa87>>::try_from(&sig_bytes[..]) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_opt = Signature::<MlDsa87>::decode(&sig_arr);
    let sig = match sig_opt {
        Some(s) => s,
        None => return false,
    };
    pk.verify(data, &sig).is_ok()
}

/// ML‑DSA‑65 署名 (Base64 出力)
pub fn sign_with_mlds65(private_key_b64: &str, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let sk_bytes = BASE64.decode(private_key_b64)?;
    let sk_arr = <EncodedSigningKey<MlDsa65>>::try_from(&sk_bytes[..])?;
    let sk = SigningKey::<MlDsa65>::decode(&sk_arr);
    let sig: Signature<MlDsa65> = sk.sign(data);
    Ok(BASE64.encode(sig.to_bytes()))
}

/// ML‑DSA‑65 検証
pub fn verify_with_mlds65(public_key_b64: &str, data: &[u8], signature_b64: &str) -> bool {
    let pk_bytes = match BASE64.decode(public_key_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let pk_arr = match <EncodedVerifyingKey<MlDsa65>>::try_from(&pk_bytes[..]) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pk = VerifyingKey::<MlDsa65>::decode(&pk_arr);
    let sig_bytes = match BASE64.decode(signature_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig_arr = match <EncodedSignature<MlDsa65>>::try_from(&sig_bytes[..]) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_opt = Signature::<MlDsa65>::decode(&sig_arr);
    let sig = match sig_opt {
        Some(s) => s,
        None => return false,
    };
    pk.verify(data, &sig).is_ok()
}

/// ML‑DSA‑87 署名オブジェクト作成
pub fn create_signature_object_mlds87(
    private_key_b64: &str,
    data: &[u8],
    key_hash: &str,
    key_type: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let signature = sign_with_mlds87(private_key_b64, data)?;
    let obj = Sign {
        signature,
        key_hash: key_hash.to_string(),
        key_type: key_type.to_string(),
        algorithm: Some("ML-DSA-87".to_string()),
    };
    Ok(serde_json::to_string(&obj)?)
}

/// ML‑DSA‑65 署名オブジェクト作成
pub fn create_signature_object_mlds65(
    private_key_b64: &str,
    data: &[u8],
    key_hash: &str,
    key_type: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let signature = sign_with_mlds65(private_key_b64, data)?;
    let obj = Sign {
        signature,
        key_hash: key_hash.to_string(),
        key_type: key_type.to_string(),
        algorithm: Some("ML-DSA-65".to_string()),
    };
    Ok(serde_json::to_string(&obj)?)
}

/// 署名オブジェクト検証
pub fn verify_signature_object(
    public_key_b64: &str,
    signature_obj: &str,
    data: &[u8],
    expected_key_type: &str,
) -> bool {
    let obj: Sign = match serde_json::from_str(signature_obj) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if obj.key_type != expected_key_type {
        return false;
    }
    match obj.algorithm.as_deref() {
        Some("ML-DSA-87") => verify_with_mlds87(public_key_b64, data, &obj.signature),
        Some("ML-DSA-65") | None  => verify_with_mlds65(public_key_b64, data, &obj.signature),
        _ => false,
    }
}
