import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { arrayBufferToBase64, base64ToArrayBuffer, keyHash } from "./utils.ts";
import { isValidMasterKeyPrivate, isValidMasterKeyPublic, signMasterKey } from "./masterKey.ts";
import type { accountKey, EncryptedData } from "./type.ts";

export async function generateAccountKey(masterKey: {
  publicKey: string;
  privateKey: string;
}): Promise<
  {
    publickKey: string;
    privateKey: string;
    sign: string;
  } | null
> {
  if (!isValidMasterKeyPrivate(masterKey.privateKey)) {
    return null;
  }
  if (!isValidMasterKeyPublic(masterKey.publicKey)) {
    return null;
  }
  const key = ml_kem768.keygen();
  const publicKeyBinary = arrayBufferToBase64(
    key.publicKey as unknown as ArrayBuffer,
  );
  const privateKeyBinary = arrayBufferToBase64(
    key.secretKey as unknown as ArrayBuffer,
  );
  const timestamp = new Date().getTime();
  const publickKeyObj: accountKey = {
    keyType: "accountKeyPublic",
    key: publicKeyBinary,
    algorithm: "ML-KEM-768",
    timestamp: timestamp,
  };
  const privateKeyObj: accountKey = {
    keyType: "accountKeyPrivate",
    key: privateKeyBinary,
    algorithm: "ML-KEM-768",
    timestamp: timestamp,
  };
  const publickKey = JSON.stringify(publickKeyObj);
  const privateKey = JSON.stringify(privateKeyObj);
  const sign = signMasterKey(
    masterKey.privateKey,
    publickKey,
    await keyHash(masterKey.publicKey),
  );
  if (!sign) {
    return null;
  }
  return {
    publickKey: publickKey,
    privateKey: privateKey,
    sign: sign,
  };
}

export function isValidAccountKeyPublic(key: string): boolean {
  if (key.length !== 1645) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "accountKeyPublic") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 1184) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export function isValidAccountKeyPrivate(key: string): boolean {
  if (key.length !== 3266) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "accountKeyPrivate") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 2400) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export async function encryptDataAccountKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidAccountKeyPublic(key)) {
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
    encryptedData: encryptedDataString,
    iv: viString,
    cipherText: ciphertextString,
    keyType: "accountKey",
    keyHash: keyHashString,
    algorithm: "AES-GCM",
  };
  return JSON.stringify(result);
}

export function isValidEncryptedDataAccountKey(data: string): boolean {
  const { keyType, keyHash, iv, cipherText, algorithm } = JSON.parse(data);
  const sha256 = new Uint8Array(base64ToArrayBuffer(keyHash));
  if (keyType !== "accountKey") {
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

export async function decryptDataAccountKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidAccountKeyPrivate(key)) {
    return null;
  }
  if (!isValidEncryptedDataAccountKey(data)) {
    return null;
  }
  const { key: keyBinary } = JSON.parse(key);
  const { encryptedData: binaryEncryptedData, iv, cipherText } = JSON.parse(
    data,
  );
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
    new Uint8Array(base64ToArrayBuffer(binaryEncryptedData)),
  );
  return new TextDecoder().decode(decryptedData);
}

export function isValidEncryptedAccountKey(data: string): boolean {
  if (!isValidEncryptedDataShareKey(data)) {
    return false;
  }
  if (data.length !== 5966) {
    console.log(data.length);
    return false;
  }
  return true;
}

export function isValidEncryptedDataShareKey(data: string): boolean {
  const { keyType, keyHash, iv, cipherText, algorithm } = JSON.parse(data);
  const sha256 = new Uint8Array(base64ToArrayBuffer(keyHash));
  if (keyType !== "shareKey") {
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