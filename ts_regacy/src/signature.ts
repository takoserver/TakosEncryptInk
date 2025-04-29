import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { arrayBufferToBase64, base64ToArrayBuffer } from "./utils.ts";
import type { Sign } from "./type.ts";

/**
 * ML-DSA-87を使用してデータに署名する
 * @param privateKey 秘密鍵（Base64エンコード）
 * @param data 署名するデータ文字列
 * @returns 署名（Base64エンコード）
 */
export function signWithMLDSA87(
  privateKey: string,
  data: string | Uint8Array,
): string {
  try {
    const key = new Uint8Array(base64ToArrayBuffer(privateKey));
    const dataArray = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const signature = ml_dsa87.sign(key, dataArray);
    return arrayBufferToBase64(signature as unknown as ArrayBuffer);
  } catch (error) {
    console.error("ML-DSA-87署名中にエラー:", error);
    throw new Error("データの署名に失敗しました");
  }
}

/**
 * ML-DSA-87で署名を検証する
 * @param publicKey 公開鍵（Base64エンコード）
 * @param data 署名されたデータ
 * @param signature 署名（Base64エンコード）
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function verifyWithMLDSA87(
  publicKey: string,
  data: string | Uint8Array,
  signature: string,
): boolean {
  try {
    const key = new Uint8Array(base64ToArrayBuffer(publicKey));
    const dataArray = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const sig = new Uint8Array(base64ToArrayBuffer(signature));
    return ml_dsa87.verify(key, dataArray, sig);
  } catch (error) {
    console.error("ML-DSA-87検証中にエラー:", error);
    return false;
  }
}

/**
 * ML-DSA-65を使用してデータに署名する
 * @param privateKey 秘密鍵（Base64エンコード）
 * @param data 署名するデータ文字列
 * @returns 署名（Base64エンコード）
 */
export function signWithMLDSA65(
  privateKey: string,
  data: string | Uint8Array,
): string {
  try {
    const key = new Uint8Array(base64ToArrayBuffer(privateKey));
    const dataArray = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const signature = ml_dsa65.sign(key, dataArray);
    return arrayBufferToBase64(signature as unknown as ArrayBuffer);
  } catch (error) {
    console.error("ML-DSA-65署名中にエラー:", error);
    throw new Error("データの署名に失敗しました");
  }
}

/**
 * ML-DSA-65で署名を検証する
 * @param publicKey 公開鍵（Base64エンコード）
 * @param data 署名されたデータ
 * @param signature 署名（Base64エンコード）
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function verifyWithMLDSA65(
  publicKey: string,
  data: string | Uint8Array,
  signature: string,
): boolean {
  try {
    const key = new Uint8Array(base64ToArrayBuffer(publicKey));
    const dataArray = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const sig = new Uint8Array(base64ToArrayBuffer(signature));
    return ml_dsa65.verify(key, dataArray, sig);
  } catch (error) {
    console.error("ML-DSA-65検証中にエラー:", error);
    return false;
  }
}

/**
 * 署名オブジェクトを作成する（ML-DSA-87）
 * @param privateKey 秘密鍵（Base64エンコード）
 * @param data 署名するデータ
 * @param keyHash 公開鍵のハッシュ
 * @param keyType キータイプ識別子
 * @returns 署名オブジェクトのJSON文字列
 */
export function createSignatureObjectMLDSA87(
  privateKey: string,
  data: string | Uint8Array,
  keyHash: string,
  keyType: string,
): string {
  try {
    const signatureString = signWithMLDSA87(privateKey, data);
    const signResult: Sign = {
      signature: signatureString,
      keyHash: keyHash,
      keyType: keyType,
      algorithm: "ML-DSA-87",
    };
    return JSON.stringify(signResult);
  } catch (error) {
    console.error("署名オブジェクト作成中にエラー:", error);
    throw new Error("署名オブジェクトの作成に失敗しました");
  }
}

/**
 * 署名オブジェクトを作成する（ML-DSA-65）
 * @param privateKey 秘密鍵（Base64エンコード）
 * @param data 署名するデータ
 * @param keyHash 公開鍵のハッシュ
 * @param keyType キータイプ識別子
 * @returns 署名オブジェクトのJSON文字列
 */
export function createSignatureObjectMLDSA65(
  privateKey: string,
  data: string | Uint8Array,
  keyHash: string,
  keyType: string,
): string {
  try {
    const signatureString = signWithMLDSA65(privateKey, data);
    const signResult: Sign = {
      signature: signatureString,
      keyHash: keyHash,
      keyType: keyType,
      algorithm: "ML-DSA-65",
    };
    return JSON.stringify(signResult);
  } catch (error) {
    console.error("署名オブジェクト作成中にエラー:", error);
    throw new Error("署名オブジェクトの作成に失敗しました");
  }
}

/**
 * 署名オブジェクトを検証する
 * @param publicKey 公開鍵（Base64エンコード）
 * @param signatureObj 署名オブジェクトのJSON文字列
 * @param data 署名されたデータ
 * @param expectedKeyType 期待されるキータイプ
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function verifySignatureObject(
  publicKey: string,
  signatureObj: string,
  data: string | Uint8Array,
  expectedKeyType: string,
): boolean {
  try {
    const signData: Sign = JSON.parse(signatureObj);
    if (signData.keyType !== expectedKeyType) {
      return false;
    }
    
    const signature = signData.signature;
    
    // アルゴリズムによって適切な検証関数を選択
    if (signData.algorithm === "ML-DSA-87") {
      return verifyWithMLDSA87(publicKey, data, signature);
    } else if (signData.algorithm === "ML-DSA-65" || !signData.algorithm) {
      // 下位互換性のため、アルゴリズムが未指定の場合はML-DSA-65と仮定
      return verifyWithMLDSA65(publicKey, data, signature);
    }
    
    return false;
  } catch (error) {
    console.error("署名オブジェクト検証中にエラー:", error);
    return false;
  }
}