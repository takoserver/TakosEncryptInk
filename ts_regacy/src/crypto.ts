import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { arrayBufferToBase64, base64ToArrayBuffer } from "./utils.ts";

/**
 * データを公開鍵で暗号化
 * @param data 暗号化するデータ文字列
 * @param publicKey 公開鍵（Base64エンコードされた文字列）
 * @returns 暗号化結果（暗号文、セッション暗号、IV、アルゴリズム）
 */
export async function encrypt(
  data: string,
  publicKey: string,
): Promise<{ encryptedData: string; cipherText: string; iv: string; algorithm: string }> {
  try {
    const key = new Uint8Array(base64ToArrayBuffer(publicKey));
    const { sharedSecret, cipherText } = ml_kem768.encapsulate(key);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // AES-GCMでimport
    const aesKey = await crypto.subtle.importKey(
      "raw",
      sharedSecret,
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );
    
    // 暗号化実行
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      aesKey,
      new TextEncoder().encode(data),
    );
    
    return {
      encryptedData: arrayBufferToBase64(encryptedData),
      cipherText: arrayBufferToBase64(cipherText as unknown as ArrayBuffer),
      iv: arrayBufferToBase64(iv as unknown as ArrayBuffer),
      algorithm: "AES-GCM", // アルゴリズムを追加
    };
  } catch (error) {
    console.error("暗号化中にエラー:", error);
    throw new Error("データの暗号化に失敗しました");
  }
}

/**
 * 暗号化されたデータを秘密鍵で復号
 * @param encryptedData 暗号化されたデータ（Base64エンコード）
 * @param cipherText セッション暗号（Base64エンコード）
 * @param iv 初期化ベクトル（Base64エンコード）
 * @param privateKey 秘密鍵（Base64エンコード）
 * @returns 復号されたデータ文字列
 */
export async function decrypt(
  encryptedData: string,
  cipherText: string,
  iv: string,
  privateKey: string,
): Promise<string> {
  try {
    const key = new Uint8Array(base64ToArrayBuffer(privateKey));
    const cipherTextArray = new Uint8Array(base64ToArrayBuffer(cipherText));
    const ivArray = new Uint8Array(base64ToArrayBuffer(iv));
    
    // 共有秘密の復号
    const sharedSecret = ml_kem768.decapsulate(cipherTextArray, key);
    
    // AES-GCMでimport
    const aesKey = await crypto.subtle.importKey(
      "raw",
      sharedSecret,
      { name: "AES-GCM" },
      false,
      ["decrypt"],
    );
    
    // 復号実行
    const decryptedData = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivArray,
      },
      aesKey,
      new Uint8Array(base64ToArrayBuffer(encryptedData)),
    );
    
    return new TextDecoder().decode(decryptedData);
  } catch (error) {
    console.error("復号中にエラー:", error);
    throw new Error("データの復号に失敗しました");
  }
}

/**
 * 対称鍵でデータを暗号化
 * @param data 暗号化するデータ文字列
 * @param key 対称鍵（Base64エンコードされた文字列）
 * @returns 暗号化結果（暗号文、IV、アルゴリズム）
 */
export async function encryptWithSymmetricKey(
  data: string,
  key: string,
): Promise<{ encryptedData: string; iv: string; algorithm: string }> {
  try {
    const keyBytes = new Uint8Array(base64ToArrayBuffer(key));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // AES-GCMでimport
    const aesKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"],
    );
    
    // 暗号化実行
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      aesKey,
      new TextEncoder().encode(data),
    );
    
    return {
      encryptedData: arrayBufferToBase64(encryptedData),
      iv: arrayBufferToBase64(iv as unknown as ArrayBuffer),
      algorithm: "AES-GCM",
    };
  } catch (error) {
    console.error("対称鍵暗号化中にエラー:", error);
    throw new Error("データの暗号化に失敗しました");
  }
}

/**
 * 対称鍵で暗号化されたデータを復号
 * @param encryptedData 暗号化されたデータ（Base64エンコード）
 * @param iv 初期化ベクトル（Base64エンコード）
 * @param key 対称鍵（Base64エンコード）
 * @returns 復号されたデータ文字列
 */
export async function decryptWithSymmetricKey(
  encryptedData: string,
  iv: string,
  key: string,
): Promise<string> {
  try {
    const keyBytes = new Uint8Array(base64ToArrayBuffer(key));
    const ivArray = new Uint8Array(base64ToArrayBuffer(iv));
    
    // AES-GCMでimport
    const aesKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
    
    // 復号実行
    const decryptedData = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: ivArray,
      },
      aesKey,
      new Uint8Array(base64ToArrayBuffer(encryptedData)),
    );
    
    return new TextDecoder().decode(decryptedData);
  } catch (error) {
    console.error("対称鍵での復号中にエラー:", error);
    throw new Error("データの復号に失敗しました");
  }
}