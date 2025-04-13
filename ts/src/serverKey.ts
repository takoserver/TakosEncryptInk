import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { arrayBufferToBase64, base64ToArrayBuffer, keyHash } from "./utils.ts";
import type { Sign } from "./type.ts";

/**
 * サーバーキーペアを生成する
 * @returns 公開鍵と秘密鍵のペア
 */
export function generateServerKey(): {
  publicKey: string;
  privateKey: string;
} {
  try {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const key = ml_dsa65.keygen(seed);
    const timestamp = new Date().getTime();
    
    const publicKey = {
      keyType: "serverKeyPublic",
      key: arrayBufferToBase64(key.publicKey as unknown as ArrayBuffer),
      timestamp: timestamp
    };
    
    const privateKey = {
      keyType: "serverKeyPrivate",
      key: arrayBufferToBase64(key.secretKey as unknown as ArrayBuffer),
      timestamp: timestamp
    };
    
    return {
      publicKey: JSON.stringify(publicKey),
      privateKey: JSON.stringify(privateKey),
    };
  } catch (error) {
    console.error("サーバーキー生成中にエラー:", error);
    throw new Error("サーバーキーの生成に失敗しました");
  }
}

/**
 * サーバーキーの秘密鍵が有効かどうかを検証する
 * @param key 検証するサーバーキーの秘密鍵
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidServerKeyPrivate(key: string): boolean {
  try {
    const { key: keyBinary, keyType } = JSON.parse(key);
    if (keyType !== "serverKeyPrivate") {
      return false;
    }
    const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
    if (keyBinaryArray.length !== 4032) { // ML-DSA-65の秘密鍵サイズ
      console.log("サーバーキー秘密鍵のバイナリ長が無効:", keyBinaryArray.length);
      return false;
    }
    return true;
  } catch (error) {
    console.error("サーバーキー秘密鍵検証中にエラー:", error);
    return false;
  }
}

/**
 * サーバーキーの公開鍵が有効かどうかを検証する
 * @param key 検証するサーバーキーの公開鍵
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidServerKeyPublic(key: string): boolean {
  try {
    const { key: keyBinary, keyType } = JSON.parse(key);
    if (keyType !== "serverKeyPublic") {
      return false;
    }
    const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
    if (keyBinaryArray.length !== 1952) { // ML-DSA-65の公開鍵サイズ
      console.log("サーバーキー公開鍵のバイナリ長が無効:", keyBinaryArray.length);
      return false;
    }
    return true;
  } catch (error) {
    console.error("サーバーキー公開鍵検証中にエラー:", error);
    return false;
  }
}

/**
 * サーバーキーで署名を作成する
 * @param data 署名するデータ
 * @param privateKey サーバーキーの秘密鍵
 * @returns 署名文字列、またはエラー時はnull
 */
export function signDataWithServerKey(
  data: string,
  privateKey: string,
): string | null {
  if (!isValidServerKeyPrivate(privateKey)) {
    return null;
  }
  
  try {
    const { key: keyBinary } = JSON.parse(privateKey);
    const dataArray = new TextEncoder().encode(data);
    const signature = ml_dsa65.sign(
      new Uint8Array(base64ToArrayBuffer(keyBinary)),
      dataArray,
    );
    const signString = arrayBufferToBase64(signature as unknown as ArrayBuffer);
    return signString;
  } catch (error) {
    console.error("サーバーキー署名作成中にエラー:", error);
    return null;
  }
}

/**
 * サーバーキーの署名情報を作成する
 * @param data 署名するデータ
 * @param privateKey サーバーキーの秘密鍵
 * @param pubKeyHash 公開鍵のハッシュ
 * @returns 署名オブジェクトのJSON文字列、またはエラー時はnull
 */
export async function signServerKey(
  privateKey: string,
  data: string,
  pubKeyHash: string,
): Promise<string | null> {
  if (!isValidServerKeyPrivate(privateKey)) {
    return null;
  }
  
  try {
    const { key: keyBinary } = JSON.parse(privateKey);
    const dataArray = new TextEncoder().encode(data);
    const signature = ml_dsa65.sign(
      new Uint8Array(base64ToArrayBuffer(keyBinary)),
      dataArray,
    );
    const signString = arrayBufferToBase64(signature as unknown as ArrayBuffer);
    const signResult: Sign = {
      signature: signString,
      keyHash: pubKeyHash,
      keyType: "serverKey",
      algorithm: "ML-DSA-65", // アルゴリズムを追加
    };
    return JSON.stringify(signResult);
  } catch (error) {
    console.error("サーバーキー署名作成中にエラー:", error);
    return null;
  }
}

/**
 * サーバーキーの署名を検証する
 * @param data 署名されたデータ
 * @param signature 署名文字列
 * @param publicKey サーバーキーの公開鍵
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function verifyDataWithServerKey(
  data: string,
  signature: string,
  publicKey: string,
): boolean {
  if (!isValidServerKeyPublic(publicKey)) {
    return false;
  }
  
  try {
    const { key: keyBinary } = JSON.parse(publicKey);
    return ml_dsa65.verify(
      new Uint8Array(base64ToArrayBuffer(keyBinary)),
      new TextEncoder().encode(data),
      new Uint8Array(base64ToArrayBuffer(signature)),
    );
  } catch (error) {
    console.error("サーバーキー署名検証中にエラー:", error);
    return false;
  }
}

/**
 * サーバーキーの署名オブジェクトを検証する
 * @param publicKey サーバーキーの公開鍵
 * @param sign 署名オブジェクトのJSON文字列
 * @param data 署名されたデータ
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function verifyServerKey(
  publicKey: string,
  sign: string,
  data: string,
): boolean {
  if (!isValidServerKeyPublic(publicKey)) {
    return false;
  }
  
  try {
    const { key: keyBinary } = JSON.parse(publicKey);
    const signData: Sign = JSON.parse(sign);
    if (signData.keyType !== "serverKey") {
      return false;
    }
    const dataArray = new TextEncoder().encode(data);
    return ml_dsa65.verify(
      new Uint8Array(base64ToArrayBuffer(keyBinary)),
      dataArray,
      new Uint8Array(base64ToArrayBuffer(signData.signature)),
    );
  } catch (error) {
    console.error("サーバーキー署名検証中にエラー:", error);
    return false;
  }
}

/**
 * サーバーキーの署名が有効かどうかを検証する
 * @param sign 検証する署名
 * @returns 検証結果（true: 有効、false: 無効）
 */
export function isValidSignServerKey(sign: string): boolean {
  try {
    const { keyHash, signature, keyType } = JSON.parse(sign);
    if (keyType !== "serverKey") {
      return false;
    }
    if (keyHash.length !== 44) { // Base64エンコードされたSHA-256ハッシュのサイズ
      console.log("サーバーキー署名のハッシュ長が無効:", keyHash.length);
      return false;
    }
    if (signature.length !== 4412) { // ML-DSA-65の署名サイズ
      console.log("サーバーキー署名の署名長が無効:", signature.length);
      return false;
    }
    return true;
  } catch (error) {
    console.error("サーバーキー署名検証中にエラー:", error);
    return false;
  }
}