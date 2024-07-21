import { AeadId, CipherSuite, KdfId, KemId } from "hpke-js";

async function doHpke() {
  const privateKey = "xKV9ndw-BOxWKWjyalA7LBovXMvybM6MFAt14BjBXFo=";
  const publicKey = "BM-zS0bU6vBrqgMBMpAZEU7xKmvgqn3Uz36zbX1Yh-XC2KL-pLcHx3Jm8JVnv2U7aLf5rdTe3grVz42k6HuS4bA=";

  const suite = new CipherSuite({
    kem: KemId.DhkemP256HkdfSha256,
    kdf: KdfId.HkdfSha256,
    aead: AeadId.Aes128Gcm,
  });

  const publicCryptoKey = await suite.kem.deserializePublicKey(Buffer.from(publicKey, 'base64'));
  const privateCryptoKey = await suite.kem.deserializePrivateKey(Buffer.from(privateKey, 'base64'));

  // A sender encrypts a message with the recipient public key.
  const sender = await suite.createSenderContext({
    recipientPublicKey: publicCryptoKey,
  });
  const ct = await sender.seal(new TextEncoder().encode("Hello world!"));

  // The recipient decrypts it.
  const recipient = await suite.createRecipientContext({
    recipientKey: privateCryptoKey,
    enc: sender.enc,
  });
  const pt = await recipient.open(ct);

  // Hello world!
  console.log("decrypted: ", new TextDecoder().decode(pt));
}

try {
  doHpke();
} catch (e) {
  console.log("failed:", (e as Error).message);
}