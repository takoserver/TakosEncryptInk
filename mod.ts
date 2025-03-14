import { ml_kem768 } from "@noble/post-quantum/ml-kem";
import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa";
import { arrayBufferToBase64, base64ToArrayBuffer } from "./utils/buffers.ts";
import { keyHash } from "./utils/keyHash.ts";
import type {
  accountKey,
  deviceKey,
  EncryptedData,
  identityKey,
  masterKey,
  migrateKey,
  migrateSignKey,
  roomKey,
  shareKey,
  shareSignKey,
  Sign,
} from "./type.ts";

export { keyHash };

export function isValidUUIDv7(uuid: string): boolean {
  const uuidV7Regex =
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidV7Regex.test(uuid);
}

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
    timestamp: timestamp,
    sessionUuid: uuid,
  };
  const privateKeyObj: identityKey = {
    keyType: "identityKeyPrivate",
    key: privateKeyBinary,
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
    timestamp: timestamp,
  };
  const privateKeyObj: accountKey = {
    keyType: "accountKeyPrivate",
    key: privateKeyBinary,
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
  };
  return JSON.stringify(result);
}

export function isValidEncryptedDataAccountKey(data: string): boolean {
  const { keyType, keyHash, iv, cipherText } = JSON.parse(data);
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

export function isValidEncryptedDataRoomKey(data: string): boolean {
  const { keyType, keyHash, iv } = JSON.parse(data);
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
  };
  return JSON.stringify(result);
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
  identityKey: string,
  pubKeyHash: string,
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
    if (!isValidMasterKeyPublic(k.masterKey)) {
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
  const metadataSign = signIdentityKey(identityKey, metadata, pubKeyHash);
  if (!metadataSign) {
    return null;
  }
  const roomKeySign = signIdentityKey(identityKey, roomKey, pubKeyHash);
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

export async function encryptMessage(
  message: {
    type: "text" | "image" | "video" | "audio" | "file" | "thumbnail";
    content: string;
    channel: string;
    timestamp: number;
    isLarge: boolean;
    original?: string;
    reply?: { id: string }; // 返信先情報の追加
    mention: string[]; // メンション対象ユーザーの追加
  },
  roomKey: string,
  identityKey: {
    privateKey: string;
    pubKeyHash: string;
  },
  roomid: string,
): Promise<
  {
    message: string;
    sign: string;
  } | null
> {
  if (!isValidRoomKey(roomKey)) {
    return null;
  }
  if (!isValidIdentityKeyPrivate(identityKey.privateKey)) {
    return null;
  }
  const messageContent = JSON.stringify({
    type: message.type,
    content: message.content,
    reply: message.reply, // 返信情報を含める
    mention: message.mention || [], // メンション情報を含める
  });
  const data = await encryptDataRoomKey(roomKey, messageContent);
  if (!data) {
    return null;
  }
  const messageObj = {
    encrypted: true,
    value: data,
    channel: message.channel,
    timestamp: message.timestamp,
    isLarge: message.isLarge,
    original: message.original,
    roomid: roomid,
  };
  const messageString = JSON.stringify(messageObj);
  const sign = signIdentityKey(
    identityKey.privateKey,
    messageString,
    identityKey.pubKeyHash,
  );
  if (!sign) {
    return null;
  }
  return {
    message: messageString,
    sign: sign,
  };
}

export async function decryptMessage(
  message: {
    message: string;
    sign: string;
  },
  serverData: {
    timestamp: number;
  },
  roomKey: string,
  identityKey: string,
  roomid: string,
): Promise<
  {
    type: "text" | "image" | "video" | "audio" | "file" | "thumbnail";
    content: string;
    channel: string;
    timestamp: number;
    isLarge: boolean;
    original?: string;
    reply?: { id: string }; // 返信先情報を追加
    mention: string[]; // メンション対象ユーザーを追加
  } | null
> {
  if (!isValidRoomKey(roomKey)) {
    return null;
  }
  if (!isValidIdentityKeyPublic(identityKey)) {
    return null;
  }
  const { message: messageString, sign: signString } = message;
  if (!verifyIdentityKey(identityKey, signString, messageString)) {
    return null;
  }
  const messageObj = JSON.parse(messageString);
  if (!messageObj.encrypted) {
    return messageObj;
  }
  // messageObj.timestampとserverData.timestampの誤差が1分以内かどうか確認
  if (Math.abs(messageObj.timestamp - serverData.timestamp) > 60000) {
    return null;
  }
  const data = await decryptDataRoomKey(roomKey, messageObj.value);
  if (!data) {
    return null;
  }
  if (roomid !== messageObj.roomid) {
    return null;
  }
  const messageContent = JSON.parse(data);
  return {
    type: messageContent.type,
    content: messageContent.content,
    channel: messageObj.channel,
    timestamp: messageObj.timestamp,
    isLarge: messageObj.isLarge,
    original: messageObj.original,
    reply: messageContent.reply, // 返信情報を復号結果に含める
    mention: messageContent.mention || [], // メンション情報を復号結果に含める
  };
}

export async function generateShareKey(
  masterKey: string,
  sessionUUID: string,
): Promise<
  {
    publickKey: string;
    privateKey: string;
    sign: string;
  } | null
> {
  if (!isValidMasterKeyPrivate(masterKey)) {
    return null;
  }
  if (!isValidUUIDv7(sessionUUID)) {
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
  const publickKeyObj: shareKey = {
    keyType: "shareKeyPublic",
    key: publicKeyBinary,
    timestamp: timestamp,
    sessionUuid: sessionUUID,
  };
  const privateKeyObj: shareKey = {
    keyType: "shareKeyPrivate",
    key: privateKeyBinary,
    timestamp: timestamp,
    sessionUuid: sessionUUID,
  };
  const publickKey = JSON.stringify(publickKeyObj);
  const privateKey = JSON.stringify(privateKeyObj);
  const sign = await signMasterKey(
    masterKey,
    publickKey,
    await keyHash(masterKey),
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

export function isValidShareKeyPublic(key: string): boolean {
  if (key.length !== 1696) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "shareKeyPublic") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 1184) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export function isValidShareKeyPrivate(key: string): boolean {
  if (key.length !== 3317) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "shareKeyPrivate") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 2400) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export async function encryptDataShareKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidShareKeyPublic(key)) {
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
    keyType: "shareKey",
    keyHash: keyHashString,
    encryptedData: encryptedDataString,
    iv: viString,
    cipherText: ciphertextString,
  };
  return JSON.stringify(result);
}

export async function decryptDataShareKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidShareKeyPrivate(key)) {
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
  const { keyType, keyHash, iv, cipherText } = JSON.parse(data);
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

export async function generateShareSignKey(
  masterKey: {
    publicKey: string;
    privateKey: string;
  },
  sessionUUID: string,
): Promise<{ publickKey: string; privateKey: string; sign: string }> {
  if (!isValidMasterKeyPrivate(masterKey.privateKey)) {
    throw new Error("masterKey is invalid");
  }
  if (!isValidUUIDv7(sessionUUID)) {
    throw new Error("sessionUUID is invalid");
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
  const publickKey: shareSignKey = {
    keyType: "shareSignKeyPublic",
    key: publicKeyBinary,
    timestamp: timestamp,
    sessionUuid: sessionUUID,
  };
  const privateKey: shareSignKey = {
    keyType: "shareSignKeyPrivate",
    key: privateKeyBinary,
    timestamp: timestamp,
    sessionUuid: sessionUUID,
  };
  const publickKeyString = JSON.stringify(publickKey);
  const privateKeyString = JSON.stringify(privateKey);
  const sign = await signMasterKey(
    masterKey.privateKey,
    publickKeyString,
    await keyHash(masterKey.publicKey),
  );
  if (!sign) {
    throw new Error("sign error");
  }
  return {
    publickKey: publickKeyString,
    privateKey: privateKeyString,
    sign: sign,
  };
}

export function isValidShareSignKeyPublic(key: string): boolean {
  if (key.length !== 2724) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "shareSignKeyPublic") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 1952) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export function isValidShareSignKeyPrivate(key: string): boolean {
  if (key.length !== 5497) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "shareSignKeyPrivate") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 4032) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export function signDataShareSignKey(
  key: string,
  data: string,
  pubKeyHash: string,
): string | null {
  if (!isValidShareSignKeyPrivate(key)) {
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
    keyType: "shareSignKey",
  };
  return JSON.stringify(signResult);
}

export function verifyDataShareSignKey(
  key: string,
  sign: string,
  data: string,
): boolean {
  if (!isValidShareSignKeyPublic(key)) {
    return false;
  }
  const { key: keyBinary } = JSON.parse(key);
  const signData: Sign = JSON.parse(sign);
  if (signData.keyType !== "shareSignKey") {
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
export function isValidSignShareSignKey(sign: string): boolean {
  const { keyHash, signature, keyType } = JSON.parse(sign);
  if (sign.length !== 4510) {
    console.log(sign.length);
    return false;
  }
  if (keyType !== "shareSignKey") {
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
  const { keyType, keyHash, iv, cipherText } = JSON.parse(data);
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

export async function generateDeviceKey(): Promise<string> {
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
  const deviceKey: deviceKey = {
    keyType: "deviceKey",
    key: keyBinaryString,
  };
  return JSON.stringify(deviceKey);
}

export function isValidDeviceKey(key: string): boolean {
  if (key.length !== 76) {
    console.log(key.length);
    return false;
  }
  const { key: keyBinary, keyType } = JSON.parse(key);
  if (keyType !== "deviceKey") {
    return false;
  }
  const keyBinaryArray = new Uint8Array(base64ToArrayBuffer(keyBinary));
  if (keyBinaryArray.length !== 32) {
    console.log(keyBinaryArray.length);
    return false;
  }
  return true;
}

export async function encryptDataDeviceKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidDeviceKey(key)) {
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
    keyType: "deviceKey",
    keyHash: await keyHash(key),
    encryptedData: encryptedDataString,
    iv: viString,
  };
  return JSON.stringify(result);
}

export async function decryptDataDeviceKey(
  key: string,
  data: string,
): Promise<string | null> {
  if (!isValidDeviceKey(key)) {
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

function generateServerKey(): {
  public: string;
  private: string;
} {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const key = ml_dsa65.keygen(seed);
  return {
    public: arrayBufferToBase64(key.publicKey as unknown as ArrayBuffer),
    private: arrayBufferToBase64(key.secretKey as unknown as ArrayBuffer),
  };
}

function signData(data: string, secretKey: string): string {
  const key = base64ToArrayBuffer(secretKey);
  return arrayBufferToBase64(
    (ml_dsa65.sign(
      new Uint8Array(key),
      new TextEncoder().encode(data),
    )) as unknown as ArrayBuffer,
  );
}

function verifyData(
  data: string,
  signature: string,
  publicKey: string,
): boolean {
  const key = base64ToArrayBuffer(publicKey);
  return ml_dsa65.verify(
    new Uint8Array(key),
    new TextEncoder().encode(data),
    new Uint8Array(base64ToArrayBuffer(signature)),
  );
}

export { generateServerKey, signData, verifyData };

export function isValidkeyPairSign(
  keyPair: { public: string; private: string },
): boolean {
  const keyObj = JSON.parse(keyPair.public);
  const signText = "test";
  if (keyObj.keyType == "masterKeyPublic") {
    const sign = ml_dsa87.sign(
      new Uint8Array(base64ToArrayBuffer(JSON.parse(keyPair.private).key)),
      new TextEncoder().encode(signText),
    );
    const verify = ml_dsa87.verify(
      new Uint8Array(base64ToArrayBuffer(JSON.parse(keyPair.public).key)),
      new TextEncoder().encode(signText),
      sign,
    );
    return verify;
  }
  if (
    keyObj.keyType == "shareSignKeyPublic" ||
    keyObj.keyType == "identityKeyPublic" ||
    keyObj.keyType == "migrateSignKeyPublic"
  ) {
    const sign = ml_dsa65.sign(
      new Uint8Array(base64ToArrayBuffer(JSON.parse(keyPair.private).key)),
      new TextEncoder().encode(signText),
    );
    const verify = ml_dsa65.verify(
      new Uint8Array(base64ToArrayBuffer(JSON.parse(keyPair.public).key)),
      new TextEncoder().encode(signText),
      sign,
    );
    return verify;
  }
  console.error("error KeyType:", keyObj.keyType);
  return false;
}

export function isValidkeyPairEncrypt(
  keyPair: { public: string; private: string },
): boolean {
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
}

export function isValidMessage(message: string): boolean {
  try {
    const messageObj = JSON.parse(message);
    if (messageObj.encrypted) {
      if (messageObj.channel.length > 100) {
        return false;
      }
      if (new Date(messageObj.timestamp).getTime() !== messageObj.timestamp) {
        return false;
      }
      if (typeof messageObj.isLarge !== "boolean") {
        return false;
      }
      if (!isValidEncryptedDataRoomKey(messageObj.value)) {
        return false;
      }
      return true;
    } else {
      // 非暗号化メッセージの検証ロジックも必要に応じて追加
      const validTypes = [
        "text",
        "image",
        "video",
        "audio",
        "file",
        "thumbnail",
      ];
      if (!validTypes.includes(messageObj.value.type)) {
        return false;
      }
      if (messageObj.channel.length > 100) {
        return false;
      }
      if (typeof messageObj.isLarge !== "boolean") {
        return false;
      }
      if (
        messageObj.value.mention && !Array.isArray(messageObj.value.mention)
      ) {
        return false;
      }
      return true;
    }
  } catch (_e) {
    return false;
  }
}
