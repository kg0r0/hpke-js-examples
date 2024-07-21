import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

async function doHpke() {
  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });

  // A recipient generates a key pair.
  const rkp = await suite.kem.generateKeyPair();

  // A sender encrypts a message with the recipient public key.
  const sender = await suite.createSenderContext({
    recipientPublicKey: rkp.publicKey,
  });
  const aad = new Uint8Array([1, 2, 3, 4]);
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"), aad);

  // The recipient decrypts it.
  const recipient = await suite.createRecipientContext({
    recipientKey: rkp.privateKey,
    enc: sender.enc,
  });
  const pt = await recipient.open(ct, aad);

  // Hello world!
  console.log("decrypted: ", new TextDecoder().decode(pt));
}

try {
  doHpke();
} catch (e) {
  console.log("failed:", (e as Error).message);
}