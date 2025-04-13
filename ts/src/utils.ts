import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { decode, encode } from "base64-arraybuffer";

// --- Base64変換関数 ---

/**
 * ArrayBufferをBase64エンコードされた文字列に変換
 * @param buffer 変換するArrayBuffer
 * @returns Base64エンコードされた文字列
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return encode(buffer);
}

/**
 * Base64エンコードされた文字列をArrayBufferに変換
 * @param base64 Base64エンコードされた文字列
 * @returns 変換されたArrayBuffer
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  return decode(base64);
}

// --- 16進数変換関数 ---

/**
 * ArrayBufferを16進数文字列に変換
 * @param buffer 変換するArrayBuffer
 * @returns 16進数文字列
 */
export function arrayBufferToHex(buffer: ArrayBuffer): string {
  const byteArray = new Uint8Array(buffer);
  return Array.from(byteArray)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

// --- 共通暗号化関数 ---

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

// --- ハッシュ計算関数 ---

/**
 * キーのSHA-256ハッシュを計算し、Base64エンコードして返す
 * @param key ハッシュ化する文字列
 * @returns Base64エンコードされたハッシュ値
 */
export async function keyHash(key: string): Promise<string> {
  try {
    const keyBinary = new TextEncoder().encode(key);
    const keyHash = await crypto.subtle.digest("SHA-256", keyBinary);
    return arrayBufferToBase64(keyHash);
  } catch (error) {
    console.error("ハッシュ計算中にエラー:", error);
    throw new Error("キーのハッシュ計算に失敗しました");
  }
}

// --- 検証関数 ---

/**
 * 署名用キーペアが有効かどうかを検証
 * @param keyPair 公開鍵と秘密鍵のペア
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidkeyPairSign(
  keyPair: { public: string; private: string },
): boolean {
  try {
    const keyObj = JSON.parse(keyPair.public);
    const signText = "test";
    
    if (keyObj.keyType === "masterKeyPublic") {
      const sign = ml_dsa87.sign(
        new Uint8Array(base64ToArrayBuffer(JSON.parse(keyPair.private).key)),
        new TextEncoder().encode(signText),
      );
      return ml_dsa87.verify(
        new Uint8Array(base64ToArrayBuffer(JSON.parse(keyPair.public).key)),
        new TextEncoder().encode(signText),
        sign,
      );
    }
    
    if (
      keyObj.keyType === "shareSignKeyPublic" ||
      keyObj.keyType === "identityKeyPublic" ||
      keyObj.keyType === "migrateSignKeyPublic" ||
      keyObj.keyType === "serverKeyPublic"
    ) {
      const sign = ml_dsa65.sign(
        new Uint8Array(base64ToArrayBuffer(JSON.parse(keyPair.private).key)),
        new TextEncoder().encode(signText),
      );
      return ml_dsa65.verify(
        new Uint8Array(base64ToArrayBuffer(JSON.parse(keyPair.public).key)),
        new TextEncoder().encode(signText),
        sign,
      );
    }
    
    console.error("不明なキータイプ:", keyObj.keyType);
    return false;
  } catch (error) {
    console.error("キーペア検証中にエラー:", error);
    return false;
  }
}

/**
 * 暗号化用キーペアが有効かどうかを検証
 * @param keyPair 公開鍵と秘密鍵のペア
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidkeyPairEncrypt(
  keyPair: { public: string; private: string },
): boolean {
  try {
    const keyObj = JSON.parse(keyPair.public);
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(
      new Uint8Array(base64ToArrayBuffer(keyObj.key)),
      new Uint8Array(32),
    );
    const sharedSecret2 = ml_kem768.decapsulate(
      cipherText,
      new Uint8Array(base64ToArrayBuffer(JSON.parse(keyPair.private).key)),
    );
    return arrayBufferToBase64(sharedSecret as unknown as ArrayBuffer) ===
      arrayBufferToBase64(sharedSecret2 as unknown as ArrayBuffer);
  } catch (error) {
    console.error("暗号鍵ペア検証中にエラー:", error);
    return false;
  }
}

/**
 * ランダムな文字列を生成する
 * @param length 生成する文字列の長さ
 * @returns ランダム文字列
 */
export function generateRandomString(length: number): string {
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += characters.charAt(randomValues[i] % characters.length);
  }
  return result;
}