const { webcrypto } = require("crypto");
const { subtle } = webcrypto;
const fs = require("fs");
const path = require("path");

// Helper: ArrayBuffer to hex
function bufToHex(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

// Helper: Hex string to ArrayBuffer
function hexToBuf(hexString) {
  if (hexString.startsWith('0x')) {
    hexString = hexString.slice(2);
  }
  const view = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < view.length; i++) {
    view[i] = parseInt(hexString.substring(i * 2, i * 2 + 2), 16);
  }
  return view.buffer;
}

async function runTests() {
  console.log("=== STARTING AUTOMATED INTEGRATION TESTS (WEB CRYPTO) ===");

  // 1. Generate Key Pair (ECDSA P-256)
  console.log("\n1. Generating ECDSA P-256 key pair...");
  const keyPair = await subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  // Export raw public key (65 bytes uncompressed)
  const rawPubKey = await subtle.exportKey("raw", keyPair.publicKey);
  const pubKeyHex = "0x" + bufToHex(rawPubKey);
  console.log(`Public key generated (${rawPubKey.byteLength} bytes): ${pubKeyHex.substring(0, 30)}...`);

  // 2. Create Unique Mock PDF and Hash it
  console.log("\n2. Creating unique mock PDF and hashing it...");
  const uniqueContent = `%PDF-1.4 mock content with timestamp ${Date.now()} and random ${Math.random()}`;
  const pdfBuffer = Buffer.from(uniqueContent);
  
  // Hash mock PDF using SHA-256
  const hashBuffer = await subtle.digest("SHA-256", pdfBuffer);
  const hashHex = "0x" + bufToHex(hashBuffer);
  console.log(`SHA-256 Hash of mock PDF: ${hashHex}`);

  // 3. Sign the Hash using the Private Key
  console.log("\n3. Signing hash...");
  const signatureBuffer = await subtle.sign(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    keyPair.privateKey,
    hashBuffer
  );
  const sigHex = "0x" + bufToHex(signatureBuffer);
  console.log(`Signature generated (${signatureBuffer.byteLength} bytes): ${sigHex.substring(0, 30)}...`);

  // 4. Send Registration Transaction to Express server
  console.log("\n4. Submitting registration to Express Relayer...");
  const payload = {
    docHash: hashHex,
    fileName: "document.pdf",
    signature: sigHex,
    publicKey: pubKeyHex,
  };

  const registerRes = await fetch("http://127.0.0.1:3000/api/blockchain/record", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  const registerData = await registerRes.json();
  if (registerRes.ok) {
    console.log("Registration succeeded!");
    console.log(`Transaction Hash: ${registerData.transactionHash}`);
    console.log(`Block Number: ${registerData.blockNumber}`);
  } else {
    console.error("Registration failed:", registerData.error);
    process.exit(1);
  }

  // 5. Query the ledger for the record
  console.log("\n5. Querying ledger for the registered document...");
  const recordRes = await fetch(`http://127.0.0.1:3000/api/blockchain/record/${hashHex}`);
  const recordData = await recordRes.json();
  if (recordRes.ok) {
    console.log("Record successfully retrieved from blockchain:");
    console.log(`- File Name: ${recordData.fileName}`);
    console.log(`- Block Timestamp: ${new Date(recordData.timestamp * 1000).toLocaleString()}`);
    console.log(`- Registered By: ${recordData.registeredBy}`);
  } else {
    console.error("Failed to query record:", recordData.error);
    process.exit(1);
  }

  // 6. Test duplicate guard (Expect Rejection)
  console.log("\n6. Testing duplicate registration rejection...");
  const dupRes = await fetch("http://127.0.0.1:3000/api/blockchain/record", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  
  const dupData = await dupRes.json();
  if (dupRes.status === 409) {
    console.log("Success: Duplicate registration was correctly blocked with 409 Conflict!");
    console.log(`Error message: "${dupData.error}"`);
  } else {
    console.error("Failed: Duplicate registration was not blocked correctly. Status:", dupRes.status);
    console.error("Error Response Payload:", JSON.stringify(dupData, null, 2));
    process.exit(1);
  }

  // 7. Verify the full ledger list
  console.log("\n7. Fetching full ledger list...");
  const listRes = await fetch("http://127.0.0.1:3000/api/blockchain/records");
  const listData = await listRes.json();
  if (listRes.ok) {
    console.log(`Ledger count: ${listData.count} record(s)`);
    console.log("Documents in Ledger:");
    listData.records.forEach((r, idx) => {
      console.log(`[${idx + 1}] Hash: ${r.docHash} | Name: ${r.fileName}`);
    });
  } else {
    console.error("Failed to list records:", listData.error);
    process.exit(1);
  }

  // 8. Programmatic Signature Verification test
  console.log("\n8. Performing programmatic signature verification...");
  const recoveredKeyHex = recordData.publicKey;
  const recoveredSigHex = recordData.signature;
  
  // Verify using Subtle Crypto
  const isSignatureValid = await subtle.verify(
    { name: "ECDSA", hash: { name: "SHA-256" } },
    await subtle.importKey(
      "raw",
      hexToBuf(recoveredKeyHex),
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    ),
    hexToBuf(recoveredSigHex),
    hashBuffer
  );
  
  if (isSignatureValid) {
    console.log("Success: Signature verified programmatically!");
  } else {
    console.error("Failed: Cryptographic signature verification failed!");
    process.exit(1);
  }

  console.log("\n=== ALL PROGRAMMATIC TESTS PASSED SUCCESSFULLY ===");
}

runTests().catch(err => {
  console.error("Test execution error:", err);
  process.exit(1);
});
