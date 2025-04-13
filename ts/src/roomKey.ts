import { arrayBufferToBase64, base64ToArrayBuffer, keyHash } from "./utils.ts";
import { isValidUUIDv7 } from "./core.ts";
import type { EncryptedData, roomKey } from "./type.ts";
import { isValidAccountKeyPublic, isValidEncryptedDataAccountKey, encryptDataAccountKey } from "./accountKey.ts";
import { signIdentityKey } from "./identityKey.ts";
import { verifyMasterKey } from "./masterKey.ts";

export async function generateRoomkey(
  sessionUUID: string,
): Promise<string | null> {
  if (!isValidUUIDv7(sessionUUID)) {
    return null;
  }
  const key = await crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true,
    ["encrypt", "decrypt"],
  );
  const keyBinary = await crypto.subtle.exportKey("raw", key);
  const keyBinaryString = arrayBufferToBase64(keyBinary);
  const timestamp = new Date().getTime();
  const roomKey: roomKey = {
    keyType: "roomKey",
    key: keyBinaryString,
    algorithm: "AES-GCM",
    timestamp: timestamp,
    sessionUuid: sessionUUID,
  };
  return JSON.stringify(roomKey);
}

export function isValidRoomKey(key: string): boolean {
  if (key.length !== 153) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "roomKey") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 32) {
    return false;
  }
  return true;
}

export async function encryptDataRoomKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidRoomKey(key)) {
    return null;
  }
  const { key: keyBinary } = JSON.parse(key);
  const dataArray = new TextEncoder().encode(data);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const importedKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(base64ToArrayBuffer(keyBinary)),
    "AES-GCM",
    true,
    ["encrypt", "decrypt"],
  );
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
    keyType: "roomKey",
    keyHash: await keyHash(key),
    encryptedData: encryptedDataString,
    iv: viString,
    algorithm: "AES-GCM",
  };
  return JSON.stringify(result);
}

export function isValidEncryptedDataRoomKey(data: string): boolean {
  const { keyType, keyHash, iv, algorithm } = JSON.parse(data);
  const sha256 = new Uint8Array(base64ToArrayBuffer(keyHash));
  if (keyType !== "roomKey") {
    return false;
  }
  if (sha256.length !== 32) {
    return false;
  }
  if (new Uint8Array(base64ToArrayBuffer(iv)).length !== 12) {
    return false;
  }
  return true;
}

export function isValidEncryptedRoomKey(data: string): boolean {
  if (!isValidEncryptedDataAccountKey(data)) {
    return false;
  }
  if (data.length !== 1820) {
    return false;
  }
  return true;
}

export async function decryptDataRoomKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidRoomKey(key)) {
    return null;
  }
  const { key: keyBinary } = JSON.parse(key);
  const { encryptedData: binaryEncryptedData, iv } = JSON.parse(data);
  const importedKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(base64ToArrayBuffer(keyBinary)),
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

export interface roomKeyMetaData {
  roomKeyHash: string;
  sharedUser: {
    userId: string; //<userId>
    masterKeyHash: string; // <sha256 encoded by base64>
    accountKeyTimeStamp: number; // <timestamp>
  }[];
}

export async function encryptRoomKeyWithAccountKeys(
  key: {
    masterKey: string;
    accountKeySign?: string;
    accountKey: string;
    userId: string;
    isVerify: boolean;
  }[],
  roomKey: string,
  identityKeyPriv: string,
  identityKeyPub: string,
): Promise<
  {
    metadata: string;
    metadataSign: string;
    encryptedData: {
      userId: string;
      encryptedData: string;
    }[];
    sign: string;
  } | null
> {
  const encryptedData = [];
  const sharedUser: {
    userId: string; //<userId>
    masterKeyHash: string; // <sha256 encoded by base64>
    accountKeyTimeStamp: number; // <timestamp>
  }[] = [];
  for (const k of key) {
    if (!isValidAccountKeyPublic(k.accountKey)) {
      return null;
    }
    if (!k.masterKey) {
      return null;
    }
    if (k.isVerify) {
      if (!k.accountKeySign) throw new Error("accountKeySign is not found");
      if (!verifyMasterKey(k.masterKey, k.accountKeySign, k.accountKey)) {
        return null;
      }
    }
    const data = await encryptDataAccountKey(k.accountKey, roomKey);
    if (!data) {
      return null;
    }
    const accountKey = JSON.parse(k.accountKey);
    sharedUser.push({
      userId: k.userId,
      masterKeyHash: await keyHash(k.masterKey),
      accountKeyTimeStamp: accountKey.timestamp,
    });
    encryptedData.push({
      userId: k.userId,
      encryptedData: data,
    });
  }
  const roomKeyHash = await keyHash(roomKey);
  const roomKeyMetaData: roomKeyMetaData = {
    roomKeyHash: roomKeyHash,
    sharedUser: sharedUser,
  };
  const metadata = JSON.stringify(roomKeyMetaData);
  const identityKeyPubHash = await keyHash(identityKeyPub);
  const metadataSign = signIdentityKey(identityKeyPriv, metadata, identityKeyPubHash);
  if (!metadataSign) {
    return null;
  }
  const roomKeySign = signIdentityKey(identityKeyPriv, roomKey, identityKeyPubHash);
  if (!roomKeySign) {
    return null;
  }
  return {
    metadata: metadata,
    metadataSign: metadataSign,
    encryptedData: encryptedData,
    sign: roomKeySign,
  };
}