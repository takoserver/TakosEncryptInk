import {
  generateMasterKey,
  isValidMasterKeyPublic,
  isValidMasterKeyPrivate,
  signMasterKey,
  verifyMasterKey,
  isValidSignMasterkey,
  generateIdentityKey,
  isValidIdentityKeyPublic,
  isValidIdentityKeyPrivate,
  signIdentityKey,
  verifyIdentityKey,
  isValidSignIdentityKey,
  generateAccountKey,
  isValidAccountKeyPublic,
  isValidAccountKeyPrivate,
  encryptDataAccountKey,
  decryptDataAccountKey,
  isValidEncryptedDataAccountKey,
  generateRoomKey,
  isValidRoomKey,
  encryptDataRoomKey,
  decryptDataRoomKey,
  isValidEncryptedDataRoomKey,
  generateShareKey,
  isValidShareKeyPublic,
  isValidShareKeyPrivate,
  encryptDataShareKey,
  decryptDataShareKey,
  isValidEncryptedDataShareKey,
  generateShareSignKey,
  isValidShareSignKeyPublic,
  isValidShareSignKeyPrivate,
  signDataShareSignKey,
  verifyDataShareSignKey,
  isValidSignShareSignKey,
  generateMigrateKey,
  isValidMigrateKeyPublic,
  isValidMigrateKeyPrivate,
  encryptDataMigrateKey,
  decryptDataMigrateKey,
  isValidEncryptedDataMigrateKey,
  generateMigrateSignKey,
  isValidMigrateSignKeyPublic,
  isValidMigrateSignKeyPrivate,
  signDataMigrateSignKey,
  verifyDataMigrateSignKey,
  isValidSignMigrateSignKey,
  generateDeviceKey,
  isValidDeviceKey,
  encryptDataDeviceKey,
  decryptDataDeviceKey,
  isValidEncryptedDataDeviceKey,
  generateServerKey,
  isValidServerKeyPublic,
  isValidServerKeyPrivate,
  signDataServerKey,
  verifyDataServerKey,
  isValidSignServerKey,
  encryptMessage,
  decryptMessage,
  isValidMessage,
  createTextContent,
  keyHash,
  isValidUUIDv7,
  encryptRoomKeyWithAccountKeys,
} from "./mod.ts";
import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import type { Sign } from "./type.ts"; // Import Sign type

const testData = "This is a test message.";
const sessionUUID = "018fdb31-0798-78a2-b4c9-e145d5b5b88e"; // Example UUIDv7

Deno.test("Master Key Tests", async () => {
  const masterKey = generateMasterKey();
  assert(isValidMasterKeyPublic(masterKey.publicKey), "Master public key should be valid");
  assert(isValidMasterKeyPrivate(masterKey.privateKey), "Master private key should be valid");
  const pubKeyHash = await keyHash(masterKey.publicKey);
  const sign = signMasterKey(masterKey.privateKey, testData, pubKeyHash);
  assert(sign, "Master key signing should succeed");
  assert(isValidSignMasterkey(sign!), "Master key signature format should be valid");
  assert(verifyMasterKey(masterKey.publicKey, sign!, testData), "Master key signature verification should succeed");
});

Deno.test("Identity Key Tests", async () => {
  const masterKey = generateMasterKey();
  const identityKey = await generateIdentityKey(sessionUUID, masterKey);
  assert(identityKey, "Identity key generation should succeed");
  assert(isValidIdentityKeyPublic(identityKey!.publicKey), "Identity public key should be valid");
  assert(isValidIdentityKeyPrivate(identityKey!.privateKey), "Identity private key should be valid");
  assert(verifyMasterKey(masterKey.publicKey, identityKey!.sign, identityKey!.publicKey), "Identity key signature from master key should be valid");

  const pubKeyHash = await keyHash(identityKey!.publicKey);
  const sign = signIdentityKey(identityKey!.privateKey, testData, pubKeyHash);
  assert(sign, "Identity key signing should succeed");
  assert(isValidSignIdentityKey(sign!), "Identity key signature format should be valid");
  assert(verifyIdentityKey(identityKey!.publicKey, sign!, testData), "Identity key signature verification should succeed");
});

Deno.test("Account Key Tests", async () => {
  const masterKey = generateMasterKey();
  const accountKey = await generateAccountKey(masterKey);
  assert(accountKey, "Account key generation should succeed");
  assert(isValidAccountKeyPublic(accountKey!.publicKey), "Account public key should be valid");
  assert(isValidAccountKeyPrivate(accountKey!.privateKey), "Account private key should be valid");
  assert(verifyMasterKey(masterKey.publicKey, accountKey!.sign, accountKey!.publicKey), "Account key signature from master key should be valid");

  const encryptedData = await encryptDataAccountKey(accountKey!.publicKey, testData);
  assert(encryptedData, "Account key encryption should succeed");
  assert(isValidEncryptedDataAccountKey(encryptedData!), "Encrypted data format should be valid");

  const decryptedData = await decryptDataAccountKey(accountKey!.privateKey, encryptedData!);
  assertEquals(decryptedData, testData, "Account key decryption should match original data");
});

Deno.test("Room Key Tests", async () => {
  const roomKey = await generateRoomKey(sessionUUID);
  assert(roomKey, "Room key generation should succeed");
  assert(isValidRoomKey(roomKey!), "Room key should be valid");

  const encryptedData = await encryptDataRoomKey(roomKey!, testData);
  assert(encryptedData, "Room key encryption should succeed");
  assert(isValidEncryptedDataRoomKey(encryptedData!), "Encrypted room key data format should be valid");

  const decryptedData = await decryptDataRoomKey(roomKey!, encryptedData!);
  assertEquals(decryptedData, testData, "Room key decryption should match original data");

  // Test encryptRoomKeyWithAccountKeys
  const masterKey1 = generateMasterKey();
  const accountKey1 = await generateAccountKey(masterKey1);
  const masterKey2 = generateMasterKey();
  const accountKey2 = await generateAccountKey(masterKey2);
  const identityKey = await generateIdentityKey(sessionUUID, masterKey1); // Use masterKey1 for identity

  assert(accountKey1, "Account key 1 generation failed");
  assert(accountKey2, "Account key 2 generation failed");
  assert(identityKey, "Identity key generation failed");

  const users = [
    { masterKey: masterKey1.publicKey, accountKeySign: accountKey1!.sign, accountKey: accountKey1!.publicKey, userId: "user1", isVerify: true },
    { masterKey: masterKey2.publicKey, accountKeySign: accountKey2!.sign, accountKey: accountKey2!.publicKey, userId: "user2", isVerify: true },
  ];

  const encryptedRoomKeyData = await encryptRoomKeyWithAccountKeys(users, roomKey!);
  assert(encryptedRoomKeyData, "Encrypting room key with account keys failed");
  assert(encryptedRoomKeyData!.length === 2, "Should have encrypted data for 2 users");

  // Decrypt for user1
  const decryptedRoomKeyUser1 = await decryptDataAccountKey(accountKey1!.privateKey, encryptedRoomKeyData![0].encryptedData);
  assertEquals(decryptedRoomKeyUser1, roomKey, "Decrypted room key for user1 should match original");

  // Decrypt for user2
  const decryptedRoomKeyUser2 = await decryptDataAccountKey(accountKey2!.privateKey, encryptedRoomKeyData![1].encryptedData);
  assertEquals(decryptedRoomKeyUser2, roomKey, "Decrypted room key for user2 should match original");

});


Deno.test("Share Key Tests", async () => {
  const masterKey = generateMasterKey();
  const shareKey = await generateShareKey(masterKey.privateKey, sessionUUID);
  assert(shareKey, "Share key generation should succeed");
  assert(isValidShareKeyPublic(shareKey!.publicKey), "Share public key should be valid");
  assert(isValidShareKeyPrivate(shareKey!.privateKey), "Share private key should be valid");
  assert(verifyMasterKey(masterKey.publicKey, shareKey!.sign, shareKey!.publicKey), "Share key signature from master key should be valid");

  const encryptedData = await encryptDataShareKey(shareKey!.publicKey, testData);
  assert(encryptedData, "Share key encryption should succeed");
  assert(isValidEncryptedDataShareKey(encryptedData!), "Encrypted share key data format should be valid");

  const decryptedData = await decryptDataShareKey(shareKey!.privateKey, encryptedData!);
  assertEquals(decryptedData, testData, "Share key decryption should match original data");
});

Deno.test("Share Sign Key Tests", async () => {
  const masterKey = generateMasterKey();
  const shareSignKey = await generateShareSignKey(masterKey, sessionUUID);
  assert(shareSignKey, "Share sign key generation should succeed");
  assert(isValidShareSignKeyPublic(shareSignKey!.publicKey), "Share sign public key should be valid");
  assert(isValidShareSignKeyPrivate(shareSignKey!.privateKey), "Share sign private key should be valid");
  assert(verifyMasterKey(masterKey.publicKey, shareSignKey!.sign, shareSignKey!.publicKey), "Share sign key signature from master key should be valid");

  const pubKeyHash = await keyHash(shareSignKey!.publicKey);
  const sign = signDataShareSignKey(shareSignKey!.privateKey, testData, pubKeyHash);
  assert(sign, "Share sign key signing should succeed");
  assert(isValidSignShareSignKey(sign!), "Share sign key signature format should be valid");
  assert(verifyDataShareSignKey(shareSignKey!.publicKey, sign!, testData), "Share sign key signature verification should succeed");
});

Deno.test("Migrate Key Tests", async () => {
  const migrateKey = generateMigrateKey();
  //
});

Deno.test("Migrate Sign Key Tests", async () => {
  const migrateSignKey = generateMigrateSignKey();
  assert(isValidMigrateSignKeyPublic(migrateSignKey.publicKey), "Migrate sign public key should be valid");
  assert(isValidMigrateSignKeyPrivate(migrateSignKey.privateKey), "Migrate sign private key should be valid");

  const pubKeyHash = await keyHash(migrateSignKey.publicKey);
  const sign = signDataMigrateSignKey(migrateSignKey.privateKey, testData, pubKeyHash);
  assert(sign, "Migrate sign key signing should succeed");
  assert(isValidSignMigrateSignKey(sign!), "Migrate sign key signature format should be valid");
  assert(verifyDataMigrateSignKey(migrateSignKey.publicKey, sign!, testData), "Migrate sign key signature verification should succeed");
});

Deno.test("Device Key Tests", async () => {
  const deviceKey = await generateDeviceKey();
  assert(isValidDeviceKey(deviceKey), "Device key should be valid");

  const encryptedData = await encryptDataDeviceKey(deviceKey, testData);
  assert(encryptedData, "Device key encryption should succeed");
  assert(isValidEncryptedDataDeviceKey(encryptedData!), "Encrypted device key data format should be valid");

  const decryptedData = await decryptDataDeviceKey(deviceKey, encryptedData!);
  assertEquals(decryptedData, testData, "Device key decryption should match original data");
});

Deno.test("Server Key Tests", async () => {
  const serverKey = generateServerKey();
  assert(isValidServerKeyPublic(serverKey.publicKey), "Server public key should be valid");
  assert(isValidServerKeyPrivate(serverKey.privateKey), "Server private key should be valid");

  const pubKeyHash = await keyHash(serverKey.publicKey);
  const sign = await signDataServerKey(serverKey.privateKey, testData, pubKeyHash);
  assert(sign, "Server key signing should succeed");
  assert(isValidSignServerKey(sign!), "Server key signature format should be valid");
  assert(verifyDataServerKey(serverKey.publicKey, sign!, testData), "Server key signature verification should succeed");
});

Deno.test("Message Encryption/Decryption Tests", async () => {
  const masterKey = generateMasterKey();
  const identityKey = await generateIdentityKey(sessionUUID, masterKey);
  const roomKey = await generateRoomKey(sessionUUID);
  const roomid = "test-room-123";

  assert(identityKey, "Identity key generation failed for message test");
  assert(roomKey, "Room key generation failed for message test");

  const textContent = createTextContent("Hello, encrypted world!");
  const messageValue: any = { // Use 'any' for simplicity in test, consider stricter type
      type: "text",
      content: textContent,
  };
  const metadata = {
      channel: "general",
      timestamp: Date.now(),
      isLarge: false,
  };
  const identityKeyInfo = {
      privateKey: identityKey!.privateKey,
      pubKeyHash: await keyHash(identityKey!.publicKey),
  };

  const encryptedMessageData = await encryptMessage(messageValue, metadata, roomKey!, identityKeyInfo, roomid);
  assert(encryptedMessageData, "Message encryption failed");
  assert(isValidMessage(encryptedMessageData!.message), "Encrypted message format should be valid");
  assert(isValidSignIdentityKey(encryptedMessageData!.sign), "Message signature format should be valid"); // Assuming identity key sign format

  const serverData = { timestamp: Date.now() }; // Simulate server timestamp
  const decryptedMessage = await decryptMessage(encryptedMessageData!, serverData, roomKey!, identityKey!.publicKey, roomid);

  assert(decryptedMessage, "Message decryption failed");
  assert(!decryptedMessage!.encrypted, "Decrypted message should have encrypted=false");
  assertEquals(decryptedMessage!.roomid, roomid, "Decrypted message roomid should match");
  assertEquals(decryptedMessage!.channel, metadata.channel, "Decrypted message channel should match");
  assertEquals(decryptedMessage!.value.type, messageValue.type, "Decrypted message content type should match");
  assertEquals(decryptedMessage!.value.content, messageValue.content, "Decrypted message content should match");

  



});

Deno.test("Utils Tests", async () => {
    const testString = "hello world";
    const hash = await keyHash(testString);
    assertEquals(hash, "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=", "keyHash result mismatch"); // Precomputed hash for "hello world"
});

Deno.test("Core Tests", () => {
    assert(isValidUUIDv7("018fdb31-0798-78a2-b4c9-e145d5b5b88e"), "Valid UUIDv7 should pass");
    assert(!isValidUUIDv7("invalid-uuid"), "Invalid UUID should fail");
    assert(!isValidUUIDv7("f81d4fae-7dec-11d0-a765-00a0c91e6bf6"), "UUIDv1 should fail"); // Example UUIDv1
    assert(!isValidUUIDv7("123e4567-e89b-12d3-a456-426614174000"), "UUIDv4 should fail"); // Example UUIDv4
});
