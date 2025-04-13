import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { arrayBufferToBase64, base64ToArrayBuffer, keyHash } from "./utils.ts";
import type { EncryptedData, migrateKey, migrateSignKey, Sign } from "./type.ts";

export function generateMigrateKey(): {
  publickKey: string;
  privateKey: string;
} {
  const key = ml_kem768.keygen();
  const publicKeyBinary = arrayBufferToBase64(
    key.publicKey as unknown as ArrayBuffer,
  );
  const privateKeyBinary = arrayBufferToBase64(
    key.secretKey as unknown as ArrayBuffer,
  );
  const publickKey: migrateKey = {
    keyType: "migrateKeyPublic",
    key: publicKeyBinary,
  };
  const privateKey: migrateKey = {
    keyType: "migrateKeyPrivate",
    key: privateKeyBinary,
  };
  return {
    publickKey: JSON.stringify(publickKey),
    privateKey: JSON.stringify(privateKey),
  };
}

export function isValidMigrateKeyPrivate(key: string): boolean {
  if (key.length !== 3240) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "migrateKeyPrivate") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 2400) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export function isValidMigrateKeyPublic(key: string): boolean {
  if (key.length !== 1619) {
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "migrateKeyPublic") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 1184) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export async function encryptDataMigrateKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidMigrateKeyPublic(key)) {
    return null;
  }
  const { key: keyBinary } = JSON.parse(key);
  const dataArray = new TextEncoder().encode(data);
  const ciphertext = ml_kem768.encapsulate(
    new Uint8Array(base64ToArrayBuffer(keyBinary)),
    new Uint8Array(32),
  );
  const ciphertextString = arrayBufferToBase64(
    ciphertext.cipherText as unknown as ArrayBuffer,
  );
  const keyHashString = await keyHash(key);
  const importedKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(ciphertext.sharedSecret),
    "AES-GCM",
    true,
    ["encrypt", "decrypt"],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv,
    },
    importedKey,
    dataArray,
  );
  const viString = arrayBufferToBase64(iv as unknown as ArrayBuffer);
  const encryptedDataString = arrayBufferToBase64(encryptedData);
  const result: EncryptedData = {
    keyType: "migrateKey",
    keyHash: keyHashString,
    encryptedData: encryptedDataString,
    iv: viString,
    cipherText: ciphertextString,
    algorithm: "AES-GCM",
  };
  return JSON.stringify(result);
}

export async function decryptDataMigrateKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidMigrateKeyPrivate(key)) {
    return null;
  }
  const { key: keyBinary } = JSON.parse(key);
  const { encryptedData, iv, cipherText } = JSON.parse(data);
  if (!cipherText) {
    return null;
  }
  const sharedSecret = ml_kem768.decapsulate(
    new Uint8Array(base64ToArrayBuffer(cipherText)),
    new Uint8Array(base64ToArrayBuffer(keyBinary)),
  );
  const importedKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(sharedSecret),
    "AES-GCM",
    true,
    ["encrypt", "decrypt"],
  );
  const decryptedData = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: new Uint8Array(base64ToArrayBuffer(iv)),
    },
    importedKey,
    new Uint8Array(base64ToArrayBuffer(encryptedData)),
  );
  return new TextDecoder().decode(decryptedData);
}

export function isValidEncryptedDataMigrateKey(data: string): boolean {
  const { keyType, keyHash, iv, cipherText, algorithm } = JSON.parse(data);
  const sha256 = new Uint8Array(base64ToArrayBuffer(keyHash));
  if (keyType !== "migrateKey") {
    return false;
  }
  if (sha256.length !== 32) {
    return false;
  }
  if (new Uint8Array(base64ToArrayBuffer(iv)).length !== 12) {
    return false;
  }
  if (new Uint8Array(base64ToArrayBuffer(cipherText)).length !== 1088) {
    return false;
  }
  return true;
}

export function generateMigrateSignKey(): {
  publickKey: string;
  privateKey: string;
} {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const key = ml_dsa65.keygen(seed);
  const publicKeyBinary = arrayBufferToBase64(
    key.publicKey as unknown as ArrayBuffer,
  );
  const privateKeyBinary = arrayBufferToBase64(
    key.secretKey as unknown as ArrayBuffer,
  );
  const publickKey: migrateSignKey = {
    keyType: "migrateSignKeyPublic",
    key: publicKeyBinary,
  };
  const privateKey: migrateSignKey = {
    keyType: "migrateSignKeyPrivate",
    key: privateKeyBinary,
  };
  return {
    publickKey: JSON.stringify(publickKey),
    privateKey: JSON.stringify(privateKey),
  };
}

export function isValidMigrateSignKeyPrivate(key: string): boolean {
  if (key.length !== 5420) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "migrateSignKeyPrivate") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 4032) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export function isValidMigrateSignKeyPublic(key: string): boolean {
  if (key.length !== 2647) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "migrateSignKeyPublic") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 1952) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export function signDataMigrateSignKey(
  key: string,
  data: string,
  pubKeyHash: string,
): string | null {
  if (!isValidMigrateSignKeyPrivate(key)) {
    return null;
  }
  const { key: keyBinary } = JSON.parse(key);
  const dataArray = new TextEncoder().encode(data);
  const signature = ml_dsa65.sign(
    new Uint8Array(base64ToArrayBuffer(keyBinary)),
    dataArray,
  );
  const signString = arrayBufferToBase64(signature as unknown as ArrayBuffer);
  const signResult: Sign = {
    signature: signString,
    keyHash: pubKeyHash,
    keyType: "migrateSignKey",
    algorithm: "ML-DSA-65",
  };
  return JSON.stringify(signResult);
}

export function verifyDataMigrateSignKey(
  key: string,
  sign: string,
  data: string,
): boolean {
  if (!isValidMigrateSignKeyPublic(key)) {
    return false;
  }
  const { key: keyBinary } = JSON.parse(key);
  const signData: Sign = JSON.parse(sign);
  if (signData.keyType !== "migrateSignKey") {
    return false;
  }
  const dataArray = new TextEncoder().encode(data);
  const verify = ml_dsa65.verify(
    new Uint8Array(base64ToArrayBuffer(keyBinary)),
    dataArray,
    new Uint8Array(base64ToArrayBuffer(signData.signature)),
  );
  return verify;
}

export function isValidSignMigrateSignKey(sign: string): boolean {
  const { keyHash, signature, keyType } = JSON.parse(sign);
  if (sign.length !== 4512) {
    console.log(sign.length);
    return false;
  }
  if (keyType !== "migrateSignKey") {
    return false;
  }
  if (keyHash.length !== 44) {
    console.log(keyHash.length);
    return false;
  }
  if (signature.length !== 4412) {
    console.log(signature.length);
    return false;
  }
  return true;
}