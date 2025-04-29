import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";

// ts版モジュール
import {
  generateAccountKey,
  encryptDataAccountKey,
  decryptDataAccountKey,
  generateRoomKey,
  encryptDataRoomKey,
  decryptDataRoomKey,
  createTextContent,
  encryptMessage,
  decryptMessage,
  generateMasterKey,
  generateIdentityKey,
  keyHash,
} from "../ts_regacy/src/mod.ts";

// wasm版モジュール
import {
  generate_account_key as wasmGenerateAccountKey,
  encrypt_data_account_key as wasmEncryptDataAccountKey,
  decrypt_data_account_key as wasmDecryptDataAccountKey,
  generate_room_key as wasmGenerateRoomKey,
  encrypt_data_room_key as wasmEncryptDataRoomKey,
  decrypt_data_room_key as wasmDecryptDataRoomKey,
  create_text_content as wasmCreateTextContent,
  encrypt_message as wasmEncryptMessage,
  decrypt_message as wasmDecryptMessage,
  generate_master_key as wasmGenerateMasterKey,
  generate_identity_key as wasmGenerateIdentityKey,
  key_hash as wasmKeyHash,
} from "takos_encrypt_ink_wasm";

const TEST_DATA = "compatibility-test";
const SESSION = "018fdb31-0798-78a2-b4c9-e145d5b5b88e";

// AccountKey: ts→wasm
Deno.test("AccountKey: ts encrypt -> wasm decrypt", async () => {
  const mk = generateMasterKey();
  const ak = await generateAccountKey(mk);
  const encTs = await encryptDataAccountKey(ak!.publicKey, TEST_DATA);
  const decWasm = wasmDecryptDataAccountKey(ak!.privateKey, encTs!);
  assertEquals(decWasm, TEST_DATA);
});
// AccountKey: wasm→ts
Deno.test("AccountKey: wasm encrypt -> ts decrypt", async () => {
  const [mp, ms] = wasmGenerateMasterKey();
  const akW = wasmGenerateAccountKey(mp, ms)!;
  const encWasm = wasmEncryptDataAccountKey(akW.publicKey, TEST_DATA);
  const decTs = await decryptDataAccountKey(akW.privateKey, encWasm!);
  assertEquals(decTs, TEST_DATA);
});

// RoomKey: ts→wasm
Deno.test("RoomKey: ts encrypt -> wasm decrypt", async () => {
  const rk = await generateRoomKey(SESSION);
  const encTs = await encryptDataRoomKey(rk!, TEST_DATA);
  const decWasm = wasmDecryptDataRoomKey(rk!, encTs!);
  assertEquals(decWasm, TEST_DATA);
});
// RoomKey: wasm→ts
Deno.test("RoomKey: wasm encrypt -> ts decrypt", () => {
  const rkW = wasmGenerateRoomKey(SESSION)!;
  const encW = wasmEncryptDataRoomKey(rkW, TEST_DATA);
  return decryptDataRoomKey(rkW, encW!).then((dec) => assertEquals(dec, TEST_DATA));
});

// Message: ts→wasm
Deno.test("Message: ts encrypt -> wasm decrypt", async () => {
  const mk = generateMasterKey();
  const ik = await generateIdentityKey(SESSION, mk);
  const rk = await generateRoomKey(SESSION);
  const txt = createTextContent("hi");
  const pubHash = await keyHash(ik!.publicKey);
  const msgTs = await encryptMessage(
    { type: "text", content: txt },
    { channel: "c", timestamp: Date.now(), isLarge: false },
    rk!,
    { privateKey: ik!.privateKey, pubKeyHash: pubHash },
    "room1",
  );
  const wrapper = msgTs!;
  const decWJson = await wasmDecryptMessage(
    wrapper.message!, wrapper.sign!,
    BigInt(Date.now()),
    rk!, ik!.publicKey, "room1",
  );
  const decW = JSON.parse(decWJson!);
  assertEquals(decW.encrypted, false);
});
// Message: wasm→ts
Deno.test("Message: wasm encrypt -> ts decrypt", async () => {
  const [mp, ms] = wasmGenerateMasterKey();
  const ikW = wasmGenerateIdentityKey(SESSION, mp, ms)!;
  const rkW = wasmGenerateRoomKey(SESSION)!;
  const txtW = wasmCreateTextContent("hello");
  const hashW = wasmKeyHash(ikW.publicKey);
  const msgWjson = wasmEncryptMessage(
    txtW!,
    JSON.stringify({ channel: "c", timestamp: Date.now(), isLarge: false }),
    rkW, ikW.privateKey, hashW, SESSION,
  )!;
  const out = await decryptMessage(
    JSON.parse(msgWjson),
    {
      timestamp: Date.now(),
    },
    rkW, ikW.publicKey, SESSION!,
  )!;
  assertEquals(out!.encrypted, false);
});
