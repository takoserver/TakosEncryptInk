import { ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { arrayBufferToBase64, base64ToArrayBuffer, keyHash } from "./utils.ts";
import type { masterKey, Sign } from "./type.ts";

export function signMasterKey(
  key: string,
  data: string,
  pubKeyHash: string,
): string | null {
  if (!isValidMasterKeyPrivate(key)) {
    return null;
  }
  const { key: keyBinary } = JSON.parse(key);
  const dataArray = new TextEncoder().encode(data);
  const signature = ml_dsa87.sign(
    new Uint8Array(base64ToArrayBuffer(keyBinary)),
    dataArray,
  );
  const signString = arrayBufferToBase64(signature as unknown as ArrayBuffer);
  const signResult: Sign = {
    signature: signString,
    keyHash: pubKeyHash,
    keyType: "masterKey",
    algorithm: "ML-DSA-87", // アルゴリズムを追加
  };
  return JSON.stringify(signResult);
}

export function verifyMasterKey(
  key: string,
  sign: string,
  data: string,
): boolean {
  if (!isValidMasterKeyPublic(key)) {
    return false;
  }
  const { key: keyBinary } = JSON.parse(key);
  const signData: Sign = JSON.parse(sign);
  if (signData.keyType !== "masterKey") {
    return false;
  }
  const dataArray = new TextEncoder().encode(data);
  const verify = ml_dsa87.verify(
    new Uint8Array(base64ToArrayBuffer(keyBinary)),
    dataArray,
    new Uint8Array(base64ToArrayBuffer(signData.signature)),
  );
  return verify;
}

export function generateMasterKey(): {
  publicKey: string;
  privateKey: string;
} {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const key = ml_dsa87.keygen(seed);
  const publicKeyBinary = arrayBufferToBase64(
    key.publicKey as unknown as ArrayBuffer,
  );
  const privateKeyBinary = arrayBufferToBase64(
    key.secretKey as unknown as ArrayBuffer,
  );
  const publickKey: masterKey = {
    keyType: "masterKeyPublic",
    key: publicKeyBinary,
  };
  const privateKey: masterKey = {
    keyType: "masterKeyPrivate",
    key: privateKeyBinary,
  };
  return {
    publicKey: JSON.stringify(publickKey),
    privateKey: JSON.stringify(privateKey),
  };
}

export function isValidMasterKeyPrivate(key: string): boolean {
  if (key.length !== 6567) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "masterKeyPrivate") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 4896) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export function isValidMasterKeyPublic(key: string): boolean {
  if (key.length !== 3494) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "masterKeyPublic") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 2592) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export function isValidSignMasterkey(sign: string): boolean {
  const { keyHash, signature, keyType } = JSON.parse(sign);
  if (sign.length !== 6267) {
    console.log(sign.length);
    return false;
  }
  if (keyType !== "masterKey") {
    return false;
  }
  if (keyHash.length !== 44) {
    console.log(keyHash.length);
    return false;
  }
  if (signature.length !== 6172) {
    console.log(signature.length);
    return false;
  }
  return true;
}