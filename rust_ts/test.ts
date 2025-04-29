import {
  key_hash as keyHash,
  is_valid_uuid_v7 as isValidUUIDv7,
  generate_master_key as generateMasterKey,
  is_valid_master_key_public as isValidMasterKeyPublic,
  is_valid_master_key_private as isValidMasterKeyPrivate,
  sign_master_key as signMasterKey,
  verify_master_key as verifyMasterKey,
  generate_identity_key as generateIdentityKey,
  is_valid_identity_key_public as isValidIdentityKeyPublic,
  is_valid_identity_key_private as isValidIdentityKeyPrivate,
  sign_identity_key as signIdentityKey,
  verify_identity_key as verifyIdentityKey,
  is_valid_sign_identity_key as isValidSignIdentityKey,
  generate_account_key as generateAccountKey,
  is_valid_account_key_public as isValidAccountKeyPublic,
  is_valid_account_key_private as isValidAccountKeyPrivate,
  encrypt_data_account_key as encryptDataAccountKey,
  decrypt_data_account_key as decryptDataAccountKey,
  is_valid_encrypted_data_account_key as isValidEncryptedDataAccountKey,
  generate_room_key as generateRoomKey,
  is_valid_room_key as isValidRoomKey,
  encrypt_data_room_key as encryptDataRoomKey,
  decrypt_data_room_key as decryptDataRoomKey,
  is_valid_encrypted_data_room_key as isValidEncryptedDataRoomKey,
  encrypt_room_key_with_account_keys as encryptRoomKeyWithAccountKeys,
  generate_share_key as generateShareKey,
  is_valid_share_key_public as isValidShareKeyPublic,
  is_valid_share_key_private as isValidShareKeyPrivate,
  encrypt_data_share_key as encryptDataShareKey,
  decrypt_data_share_key as decryptDataShareKey,
  is_valid_encrypted_data_share_key as isValidEncryptedDataShareKey,
  generate_share_sign_key as generateShareSignKey,
  is_valid_share_sign_key_public as isValidShareSignKeyPublic,
  is_valid_share_sign_key_private as isValidShareSignKeyPrivate,
  sign_data_share_sign_key as signDataShareSignKey,
  verify_data_share_sign_key as verifyDataShareSignKey,
  is_valid_sign_share_sign_key as isValidSignShareSignKey,
  generate_migrate_key as generateMigrateKey,
  is_valid_migrate_key_public as isValidMigrateKeyPublic,
  is_valid_migrate_key_private as isValidMigrateKeyPrivate,
  encrypt_data_migrate_key as encryptDataMigrateKey,
  decrypt_data_migrate_key as decryptDataMigrateKey,
  is_valid_encrypted_data_migrate_key as isValidEncryptedDataMigrateKey,
  generate_migrate_sign_key as generateMigrateSignKey,
  sign_data_migrate_sign_key as signDataMigrateSignKey,
  verify_data_migrate_sign_key as verifyDataMigrateSignKey,
  is_valid_sign_migrate_sign_key as isValidSignMigrateSignKey,
  generate_device_key as generateDeviceKey,
  is_valid_device_key as isValidDeviceKey,
  encrypt_data_device_key as encryptDataDeviceKey,
  decrypt_data_device_key as decryptDataDeviceKey,
  is_valid_encrypted_data_device_key as isValidEncryptedDataDeviceKey,
  generate_server_key as generateServerKey,
  is_valid_server_key_public as isValidServerKeyPublic,
  is_valid_server_key_private as isValidServerKeyPrivate,
  sign_data_server_key as signDataServerKey,
  verify_data_server_key as verifyDataServerKey,
  is_valid_message as isValidMessage,
  create_text_content as createTextContent,
  encrypt_message as encryptMessage,
  decrypt_message as decryptMessage,
} from "takos_encrypt_ink_wasm";
import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
// ts_regacy 互換性チェック用 import
import {

    
} from "../ts_regacy/src/mod.ts";

const testData = "hello world";
const sessionUUID = "018fdb31-0798-78a2-b4c9-e145d5b5b88e";

Deno.test("Utils Tests", async () => {
  const hash = keyHash("hello world");
  assertEquals(hash, "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=");
});

Deno.test("UUIDv7 Tests", () => {
  assert(isValidUUIDv7("018fdb31-0798-78a2-b4c9-e145d5b5b88e"));
  assert(!isValidUUIDv7("invalid-uuid"));
});

Deno.test("Master Key Tests", () => {
  const [pub, priv] = generateMasterKey();
  assert(isValidMasterKeyPublic(pub), "公開鍵が有効であるべき");
  assert(isValidMasterKeyPrivate(priv), "秘密鍵が有効であるべき");
  const nh = keyHash(pub);
  const sign = signMasterKey(priv, "test message", nh);
  assert(sign, "署名が生成されるべき");
  assert(verifyMasterKey(pub, sign!, "test message"), "署名検証に成功すべき");
});

Deno.test("Identity Key Tests", () => {
  const [masterPub, masterPriv] = generateMasterKey();
  const identityKey = generateIdentityKey(sessionUUID, masterPub, masterPriv);
  assert(identityKey, "Identity key generation should succeed");
  assert(isValidIdentityKeyPublic(identityKey!.publicKey), "Identity public key should be valid");
  assert(isValidIdentityKeyPrivate(identityKey!.privateKey), "Identity private key should be valid");
  assert(verifyMasterKey(masterPub, identityKey!.sign, identityKey!.publicKey), "Identity key signature from master key should be valid");
});

Deno.test("Account Key Tests", () => {
  const [masterPub, masterPriv] = generateMasterKey();
  const accountKey = generateAccountKey(masterPub, masterPriv);
  assert(accountKey, "Account key generation should succeed");
  assert(isValidAccountKeyPublic(accountKey!.publicKey), "Account public key should be valid");
  assert(isValidAccountKeyPrivate(accountKey!.privateKey), "Account private key should be valid");
  assert(verifyMasterKey(masterPub, accountKey!.sign, accountKey!.publicKey), "Account key signature from master key should be valid");
});

Deno.test("Room Key Tests", () => {
  const rk = generateRoomKey(sessionUUID)!;
  assert(isValidRoomKey(rk), "Room key is valid");
  const enc = encryptDataRoomKey(rk, testData)!;
  assert(isValidEncryptedDataRoomKey(enc), "Encrypted room data is valid");
  assertEquals(decryptDataRoomKey(rk, enc), testData, "Room key decryption matches");

  const [mp1, ms1] = generateMasterKey();
  const ak1 = generateAccountKey(mp1, ms1)!;
  const [mp2, ms2] = generateMasterKey();
  const ak2 = generateAccountKey(mp2, ms2)!;
  const users = [
    { accountKey: ak1.publicKey, userId: "u1" },
    { accountKey: ak2.publicKey, userId: "u2" },
  ];
  const usersJson = JSON.stringify(users);
  const encRoomJson = encryptRoomKeyWithAccountKeys(usersJson, rk)!;
  const arr = JSON.parse(encRoomJson);
  assert(Array.isArray(arr) && arr.length === 2, "Encrypted room keys for 2 users");
});

Deno.test("Share Key Tests", () => {
  const [mp, ms] = generateMasterKey();
  const sk = generateShareKey(ms, sessionUUID)!;
  assert(isValidShareKeyPublic(sk.publicKey), "Share public key valid");
  assert(isValidShareKeyPrivate(sk.privateKey), "Share private key valid");
  const ed = encryptDataShareKey(sk.publicKey, testData)!;
  assert(isValidEncryptedDataShareKey(ed), "Encrypted share data valid");
  assertEquals(decryptDataShareKey(sk.privateKey, ed), testData, "Share key decrypt matches");
});

Deno.test("Share Sign Key Tests", () => {
  const [mp, ms] = generateMasterKey();
  const ssk = generateShareSignKey(ms, sessionUUID)!;
  assert(isValidShareSignKeyPublic(ssk.publicKey), "ShareSign public key valid");
  assert(isValidShareSignKeyPrivate(ssk.privateKey), "ShareSign private key valid");
  const hash = keyHash(ssk.publicKey);
  const sign = signDataShareSignKey(ssk.privateKey, testData, hash)!;
  assert(isValidSignShareSignKey(sign), "ShareSign signature format valid");
  assert(verifyDataShareSignKey(ssk.publicKey, sign, testData), "ShareSign verify succeeds");
});

Deno.test("Migrate Key Tests", () => {
  const mk = generateMigrateKey();
  assert(isValidMigrateKeyPublic(mk.publicKey), "Migrate public key valid");
  assert(isValidMigrateKeyPrivate(mk.privateKey), "Migrate private key valid");
  const enc = encryptDataMigrateKey(mk.publicKey, testData)!;
  assert(isValidEncryptedDataMigrateKey(enc), "Encrypted migrate data valid");
  assertEquals(decryptDataMigrateKey(mk.privateKey, enc), testData, "Migrate decrypt matches");
});

Deno.test("Migrate Sign Key Tests", () => {
  const msk = generateMigrateSignKey();

  const hash = keyHash(msk.publicKey);
  const sign = signDataMigrateSignKey(msk.privateKey, testData, hash)!;
  assert(verifyDataMigrateSignKey(msk.publicKey, sign, testData), "MigrateSign verify succeeds");
});

Deno.test("Device Key Tests", () => {
  const dk = generateDeviceKey();
  assert(isValidDeviceKey(dk), "Device key valid");
  const ed = encryptDataDeviceKey(dk, testData)!;
  assert(isValidEncryptedDataDeviceKey(ed), "Encrypted device data valid");
  assertEquals(decryptDataDeviceKey(dk, ed), testData, "Device decrypt matches");
});

Deno.test("Server Key Tests", async () => {
  const sk = generateServerKey();

  const hash = await keyHash(sk.publicKey);
  const sign = await signDataServerKey(sk.privateKey, testData, hash)!;
  assert(verifyDataServerKey(sk.publicKey, sign, testData), "ServerKey verify succeeds");
});

Deno.test("Message Encryption/Decryption Tests", () => {
  const [mp, ms] = generateMasterKey();
  const ik = generateIdentityKey(sessionUUID, mp, ms)!;
  const rk = generateRoomKey(sessionUUID)!;
  const text = createTextContent("hi", undefined, undefined, undefined, undefined)!;
  const meta = JSON.stringify({ channel: "c", timestamp: Date.now(), isLarge: false });
  const msgJson = encryptMessage(text, meta, rk, ik.privateKey, keyHash(ik.publicKey), sessionUUID)!;

  // 返却される JSON ラッパーをパース
  const wrapper = JSON.parse(msgJson);
  assert(isValidMessage(wrapper.message), "Encrypted message format valid");

  const out = decryptMessage(
    wrapper.message,
    wrapper.sign,
    BigInt(Date.now()),
    rk,
    ik.publicKey,
    sessionUUID
  )!;
  const result = JSON.parse(out);
  assert(!result.encrypted, "Decrypted not encrypted");
  assertEquals(result.roomid, sessionUUID);
});