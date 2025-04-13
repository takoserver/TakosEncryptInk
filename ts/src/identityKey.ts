import { ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { arrayBufferToBase64, base64ToArrayBuffer, keyHash } from "./utils.ts";
import { isValidUUIDv7 } from "./core.ts";
import { isValidMasterKeyPrivate, isValidMasterKeyPublic, signMasterKey } from "./masterKey.ts";
import type { identityKey, Sign } from "./type.ts";

export function signIdentityKey(
  key: string,
  data: string,
  pubKeyHash: string,
): string | null {
  if (!isValidIdentityKeyPrivate(key)) {
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
    keyType: "identityKey",
    algorithm: "ML-DSA-65",
  };
  return JSON.stringify(signResult);
}

export function verifyIdentityKey(
  key: string,
  sign: string,
  data: string,
): boolean {
  if (!isValidIdentityKeyPublic(key)) {
    return false;
  }
  const { key: keyBinary } = JSON.parse(key);
  const signData: Sign = JSON.parse(sign);
  if (signData.keyType !== "identityKey") {
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

export async function generateIdentityKey(uuid: string, masterKey: {
  publicKey: string;
  privateKey: string;
}): Promise<
  {
    publickKey: string;
    privateKey: string;
    sign: string;
  } | null
> {
  if (!isValidUUIDv7(uuid)) {
    return null;
  }
  if (!isValidMasterKeyPrivate(masterKey.privateKey)) {
    return null;
  }
  if (!isValidMasterKeyPublic(masterKey.publicKey)) {
    return null;
  }
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const key = ml_dsa65.keygen(seed);
  const publicKeyBinary = arrayBufferToBase64(
    key.publicKey as unknown as ArrayBuffer,
  );
  const privateKeyBinary = arrayBufferToBase64(
    key.secretKey as unknown as ArrayBuffer,
  );
  const timestamp = new Date().getTime();
  const publickKeyObj: identityKey = {
    keyType: "identityKeyPublic",
    key: publicKeyBinary,
    algorithm: "ML-DSA-65",
    timestamp: timestamp,
    sessionUuid: uuid,
  };
  const privateKeyObj: identityKey = {
    keyType: "identityKeyPrivate",
    key: privateKeyBinary,
    algorithm: "ML-DSA-65",
    timestamp: timestamp,
    sessionUuid: uuid,
  };
  const publickKey = JSON.stringify(publickKeyObj);
  const privateKey = JSON.stringify(privateKeyObj);
  const sign = await signMasterKey(
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

export function isValidIdentityKeyPrivate(key: string): boolean {
  if (key.length !== 5496) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "identityKeyPrivate") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 4032) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export function isValidIdentityKeyPublic(key: string): boolean {
  if (key.length !== 2723) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "identityKeyPublic") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 1952) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export function isValidSignIdentityKey(sign: string): boolean {
  const { keyHash, signature, keyType } = JSON.parse(sign);
  if (sign.length !== 4509) {
    console.log(sign.length);
    return false;
  }
  if (keyType !== "identityKey") {
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