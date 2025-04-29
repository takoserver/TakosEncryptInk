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