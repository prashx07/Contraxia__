// --- Application State ---
let appState = {
  loadedPrivateKey: null,
  loadedPublicKey: null,
  activeTab: "dashboard-tab",
  selectedSignFile: null,
  selectedSignFileHash: null,
  selectedVerifyFile: null,
  selectedVerifyFileHash: null,
  networkStatus: "Disconnected",
};

// --- DOM Elements ---
const DOM = {
  tabs: document.querySelectorAll(".nav-tab"),
  sections: document.querySelectorAll(".panel-section"),
  
  // Status
  connectionStatus: document.getElementById("connectionStatus"),
  contractInfo: document.getElementById("contractInfo"),
  contractAddressDisplay: document.getElementById("contractAddressDisplay"),
  metricBlockHeight: document.getElementById("metricBlockHeight"),
  metricNetworkId: document.getElementById("metricNetworkId"),
  metricContractStatus: document.getElementById("metricContractStatus"),
  metricTotalDocs: document.getElementById("metricTotalDocs"),
  metricRpcEndpoint: document.getElementById("metricRpcEndpoint"),
  insecureContextAlert: document.getElementById("insecureContextAlert"),

  // Identity Setup
  generateKeysBtn: document.getElementById("generateKeysBtn"),
  keypairDisplay: document.getElementById("keypairDisplay"),
  privateKeyPemDisplay: document.getElementById("privateKeyPemDisplay"),
  publicKeyPemDisplay: document.getElementById("publicKeyPemDisplay"),
  downloadPrivateKeyBtn: document.getElementById("downloadPrivateKeyBtn"),
  downloadPublicKeyBtn: document.getElementById("downloadPublicKeyBtn"),
  privateKeyFileInput: document.getElementById("privateKeyFileInput"),
  keyFileDropzone: document.getElementById("keyFileDropzone"),
  privateKeyInputArea: document.getElementById("privateKeyInputArea"),
  loadPastedKeyBtn: document.getElementById("loadPastedKeyBtn"),
  loadedKeyDot: document.getElementById("loadedKeyDot"),
  loadedKeyText: document.getElementById("loadedKeyText"),

  // Sign Document
  signPdfFileInput: document.getElementById("signPdfFileInput"),
  pdfSignDropzone: document.getElementById("pdfSignDropzone"),
  pdfSignUploadText: document.getElementById("pdfSignUploadText"),
  pdfHashResultBox: document.getElementById("pdfHashResultBox"),
  signFileName: document.getElementById("signFileName"),
  signFileSize: document.getElementById("signFileSize"),
  signFileHash: document.getElementById("signFileHash"),
  signingKeyStatus: document.getElementById("signingKeyStatus"),
  signDocumentBtn: document.getElementById("signDocumentBtn"),
  signatureResultBox: document.getElementById("signatureResultBox"),
  generatedSignatureHex: document.getElementById("generatedSignatureHex"),
  exportedPublicKeyHex: document.getElementById("exportedPublicKeyHex"),
  registerBlockchainBtn: document.getElementById("registerBlockchainBtn"),
  txReceiptBox: document.getElementById("txReceiptBox"),
  receiptTxHash: document.getElementById("receiptTxHash"),
  receiptBlockNumber: document.getElementById("receiptBlockNumber"),

  // Ledger
  refreshLedgerBtn: document.getElementById("refreshLedgerBtn"),
  ledgerEmptyState: document.getElementById("ledgerEmptyState"),
  ledgerTimeline: document.getElementById("ledgerTimeline"),

  // Verifier Portal
  verifyPdfFileInput: document.getElementById("verifyPdfFileInput"),
  pdfVerifyDropzone: document.getElementById("pdfVerifyDropzone"),
  pdfVerifyUploadText: document.getElementById("pdfVerifyUploadText"),
  verifyFileStatsBox: document.getElementById("verifyFileStatsBox"),
  verifyFileName: document.getElementById("verifyFileName"),
  verifyFileHash: document.getElementById("verifyFileHash"),
  checkHashMatchRow: document.getElementById("checkHashMatchRow"),
  checkSignatureValidRow: document.getElementById("checkSignatureValidRow"),
  verificationResultBanner: document.getElementById("verificationResultBanner"),
  fetchedRecordMetadataBox: document.getElementById("fetchedRecordMetadataBox"),
  metaFileName: document.getElementById("metaFileName"),
  metaTimestamp: document.getElementById("metaTimestamp"),
  metaRegisteredBy: document.getElementById("metaRegisteredBy"),
  metaPublicKey: document.getElementById("metaPublicKey"),
  metaSignature: document.getElementById("metaSignature"),
  
  // Advanced overrides
  manualVerifyHash: document.getElementById("manualVerifyHash"),
  manualVerifySignature: document.getElementById("manualVerifySignature"),
  manualVerifyPublicKey: document.getElementById("manualVerifyPublicKey"),
  manualVerifyBtn: document.getElementById("manualVerifyBtn"),
};

// --- Cryptography Helpers (Web Crypto API) ---

// Convert ArrayBuffer to Hex string
function bufToHex(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

// Convert Hex string to ArrayBuffer
function hexToBuf(hexString) {
  if (hexString.startsWith('0x')) {
    hexString = hexString.slice(2);
  }
  const badCharacters = /[^0-9a-fA-F]/g;
  if (badCharacters.test(hexString)) {
    throw new Error("Invalid hex character sequence.");
  }
  if (hexString.length % 2 !== 0) {
    hexString = '0' + hexString;
  }
  const view = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < view.length; i++) {
    view[i] = parseInt(hexString.substring(i * 2, i * 2 + 2), 16);
  }
  return view.buffer;
}

// Convert ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Convert Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binaryString = window.atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// Format Base64 content to standard PEM string
function formatPemString(base64, headerName) {
  let result = `-----BEGIN ${headerName}-----\n`;
  for (let i = 0; i < base64.length; i += 64) {
    result += base64.substring(i, i + 64) + "\n";
  }
  result += `-----END ${headerName}-----`;
  return result;
}

// Generate an ECDSA P-256 key pair
async function generateECDSAKeyPair() {
  return await window.crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    true, // Extractable so user can download/store
    ["sign", "verify"]
  );
}

// Export CryptoKey Private Key to PEM
async function exportPrivateKeyToPem(privateKey) {
  const exported = await window.crypto.subtle.exportKey("pkcs8", privateKey);
  const base64 = arrayBufferToBase64(exported);
  return formatPemString(base64, "PRIVATE KEY");
}

// Export CryptoKey Public Key to PEM (SPKI)
async function exportPublicKeyToPem(publicKey) {
  const exported = await window.crypto.subtle.exportKey("spki", publicKey);
  const base64 = arrayBufferToBase64(exported);
  return formatPemString(base64, "PUBLIC KEY");
}

// Export CryptoKey Public Key to Raw Hex for Blockchain
async function exportPublicKeyToHex(publicKey) {
  const exported = await window.crypto.subtle.exportKey("raw", publicKey);
  return "0x" + bufToHex(exported);
}

// Import Private Key from PEM
async function importPrivateKeyFromPem(pemString) {
  const base64 = pemString
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  const buffer = base64ToArrayBuffer(base64);
  return await window.crypto.subtle.importKey(
    "pkcs8",
    buffer,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"]
  );
}

// Import Public Key from PEM
async function importPublicKeyFromPem(pemString) {
  const base64 = pemString
    .replace(/-----BEGIN PUBLIC KEY-----/, "")
    .replace(/-----END PUBLIC KEY-----/, "")
    .replace(/\s+/g, "");
  const buffer = base64ToArrayBuffer(base64);
  return await window.crypto.subtle.importKey(
    "spki",
    buffer,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

// Import Public Key from Raw Hex
async function importPublicKeyFromHex(hexString) {
  const buffer = hexToBuf(hexString);
  return await window.crypto.subtle.importKey(
    "raw",
    buffer,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

// Derive Public Key from Private Key JWK
async function derivePublicKey(privateKey) {
  const jwk = await window.crypto.subtle.exportKey("jwk", privateKey);
  const pubJwk = {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    y: jwk.y
  };
  return await window.crypto.subtle.importKey(
    "jwk",
    pubJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
}

// Hash file content to SHA-256
async function hashFile(file) {
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await window.crypto.subtle.digest("SHA-256", arrayBuffer);
  return "0x" + bufToHex(hashBuffer);
}

// Sign a hash using ECDSA private key
async function signHash(privateKey, hashHex) {
  const hashBuffer = hexToBuf(hashHex);
  const signatureBuffer = await window.crypto.subtle.sign(
    {
      name: "ECDSA",
      hash: { name: "SHA-256" },
    },
    privateKey,
    hashBuffer
  );
  return "0x" + bufToHex(signatureBuffer);
}

// Verify signature using stored public key, signature and file hash
async function verifySignature(publicKeyHex, hashHex, signatureHex) {
  try {
    const publicKey = await importPublicKeyFromHex(publicKeyHex);
    const signatureBuffer = hexToBuf(signatureHex);
    const hashBuffer = hexToBuf(hashHex);
    return await window.crypto.subtle.verify(
      {
        name: "ECDSA",
        hash: { name: "SHA-256" },
      },
      publicKey,
      signatureBuffer,
      hashBuffer
    );
  } catch (error) {
    console.error("Cryptographic verification error:", error);
    return false;
  }
}

// --- API Interactions ---

async function fetchBlockchainStatus() {
  try {
    const res = await fetch("/api/blockchain/status");
    const data = await res.json();
    
    if (data.status === "Connected") {
      appState.networkStatus = "Connected";
      DOM.connectionStatus.className = "network-status connected";
      DOM.connectionStatus.querySelector(".status-text").textContent = "Connected to Ganache";
      DOM.contractInfo.classList.remove("hidden");
      DOM.contractAddressDisplay.textContent = data.contractAddress.substring(0, 8) + "..." + data.contractAddress.slice(-6);
      
      DOM.metricBlockHeight.textContent = data.blockHeight;
      DOM.metricNetworkId.textContent = data.chainId;
      DOM.metricContractStatus.textContent = "Deployed";
      DOM.metricContractStatus.className = "metric-value text-green";
      if (DOM.metricRpcEndpoint && data.rpcUrl) {
        DOM.metricRpcEndpoint.textContent = data.rpcUrl;
      }
      
      // Update ledger count
      fetchLedgerRecords();
    } else {
      setDisconnectedState();
    }
  } catch (error) {
    console.error("Failed to connect to backend API:", error);
    setDisconnectedState();
  }
}

function setDisconnectedState() {
  appState.networkStatus = "Disconnected";
  DOM.connectionStatus.className = "network-status disconnected";
  DOM.connectionStatus.querySelector(".status-text").textContent = "Disconnected from Ganache";
  DOM.contractInfo.classList.add("hidden");
  DOM.metricBlockHeight.textContent = "--";
  DOM.metricNetworkId.textContent = "--";
  DOM.metricContractStatus.textContent = "Offline";
  DOM.metricContractStatus.className = "metric-value text-red";
  if (DOM.metricRpcEndpoint) {
    DOM.metricRpcEndpoint.textContent = "--";
  }
}

async function registerDocumentOnChain(fileName, docHash, signature, publicKey) {
  try {
    const res = await fetch("/api/blockchain/record", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fileName, docHash, signature, publicKey }),
    });
    
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to record document");
    return data;
  } catch (error) {
    alert("Blockchain Registration Failed: " + error.message);
    throw error;
  }
}

async function fetchLedgerRecords() {
  try {
    const res = await fetch("/api/blockchain/records");
    if (!res.ok) throw new Error("API request failed");
    const data = await res.json();
    
    DOM.metricTotalDocs.textContent = data.count;
    renderLedgerTimeline(data.records);
  } catch (error) {
    console.error("Failed to fetch ledger records:", error);
  }
}

async function fetchRecordByHash(hashHex) {
  try {
    const res = await fetch(`/api/blockchain/record/${hashHex}`);
    if (res.status === 404) return null;
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Failed to query record");
    return data;
  } catch (error) {
    console.error("API error searching hash:", error);
    return null;
  }
}

// --- UI Logic & Rendering ---

// Tab navigation handler
DOM.tabs.forEach(tab => {
  tab.addEventListener("click", () => {
    const targetTab = tab.getAttribute("data-tab");
    
    DOM.tabs.forEach(t => t.classList.remove("active"));
    DOM.sections.forEach(s => s.classList.remove("active"));
    
    tab.classList.add("active");
    const targetSection = document.getElementById(targetTab);
    if (targetSection) targetSection.classList.add("active");
    
    appState.activeTab = targetTab;
    
    // Refresh ledger if going to ledger explorer
    if (targetTab === "ledger-tab") {
      fetchLedgerRecords();
    }
  });
});

// Format byte size to readable string
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Update loaded key status visual card
function updateLoadedKeyUI() {
  if (appState.loadedPrivateKey) {
    DOM.loadedKeyDot.className = "status-dot green-dot";
    DOM.loadedKeyText.textContent = "Identity Loaded & Active";
    DOM.loadedKeyText.className = "status-value text-green";
    
    DOM.signingKeyStatus.textContent = "Active Key Loaded";
    DOM.signingKeyStatus.className = "text-green";
    
    if (appState.selectedSignFileHash) {
      DOM.signDocumentBtn.disabled = false;
    }
  } else {
    DOM.loadedKeyDot.className = "status-dot red-dot";
    DOM.loadedKeyText.textContent = "No Private Key Loaded";
    DOM.loadedKeyText.className = "status-value text-red";
    
    DOM.signingKeyStatus.textContent = "No Private Key Loaded";
    DOM.signingKeyStatus.className = "text-red";
    DOM.signDocumentBtn.disabled = true;
  }
}

// File download helpers
function triggerFileDownload(filename, textContent) {
  const element = document.createElement('a');
  element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(textContent));
  element.setAttribute('download', filename);
  element.style.display = 'none';
  document.body.appendChild(element);
  element.click();
  document.body.removeChild(element);
}

// Render ledger exploration list
function renderLedgerTimeline(records) {
  if (!records || records.length === 0) {
    DOM.ledgerEmptyState.classList.remove("hidden");
    DOM.ledgerTimeline.classList.add("hidden");
    return;
  }
  
  DOM.ledgerEmptyState.classList.add("hidden");
  DOM.ledgerTimeline.classList.remove("hidden");
  
  DOM.ledgerTimeline.innerHTML = "";
  
  // Sort reverse chronologically
  const sorted = [...records].sort((a, b) => b.timestamp - a.timestamp);
  
  sorted.forEach((record, idx) => {
    const blockNum = sorted.length - idx;
    
    const card = document.createElement("div");
    card.className = "block-card";
    
    const date = new Date(record.timestamp * 1000).toLocaleString();
    
    card.innerHTML = `
      <div class="block-marker">
        <span class="block-num-label">Block</span>
        <span class="block-num-val">${blockNum}</span>
      </div>
      <div class="block-body">
        <div class="block-header-info">
          <span class="block-title">${escapeHtml(record.fileName)}</span>
          <span class="block-time">${date}</span>
        </div>
        <div class="metric-container">
          <div class="metric-row block-metric">
            <span class="metric-label">Document Hash (bytes32 SHA-256):</span>
            <div class="code-block-display">${record.docHash}</div>
          </div>
          <div class="metric-row block-metric">
            <span class="metric-label">Notarizer Signature (ECDSA):</span>
            <div class="code-block-display max-height-60">${record.signature}</div>
          </div>
          <div class="metric-row block-metric">
            <span class="metric-label">Notarizer Public Key (P-256):</span>
            <div class="code-block-display max-height-60">${record.publicKey}</div>
          </div>
          <div class="metric-row">
            <span class="metric-label">Registered By:</span>
            <span class="metric-value code-text">${record.registeredBy}</span>
          </div>
        </div>
      </div>
    `;
    
    DOM.ledgerTimeline.appendChild(card);
  });
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// Reset Verification checklist
function resetVerificationChecklist() {
  DOM.checkHashMatchRow.className = "check-item";
  DOM.checkHashMatchRow.querySelector(".check-bullet").textContent = "○";
  
  DOM.checkSignatureValidRow.className = "check-item";
  DOM.checkSignatureValidRow.querySelector(".check-bullet").textContent = "○";
  
  DOM.verificationResultBanner.className = "verification-result-banner neutral-banner";
  DOM.verificationResultBanner.querySelector(".banner-status-title").textContent = "No Document Loaded";
  DOM.verificationResultBanner.querySelector(".banner-status-subtext").textContent = "Upload a PDF to execute security verification routines.";
  
  DOM.fetchedRecordMetadataBox.classList.add("hidden");
}

// Update UI with verification outcomes
function renderVerificationResults(calculatedHash, registeredRecord, signatureValid) {
  DOM.fetchedRecordMetadataBox.classList.add("hidden");
  
  if (!registeredRecord) {
    // Check 1 Fail: TAMPERED DOCUMENT (Hash not found on chain)
    DOM.checkHashMatchRow.className = "check-item fail";
    DOM.checkHashMatchRow.querySelector(".check-bullet").textContent = "✗";
    
    DOM.checkSignatureValidRow.className = "check-item warn";
    DOM.checkSignatureValidRow.querySelector(".check-bullet").textContent = "⚠";
    
    DOM.verificationResultBanner.className = "verification-result-banner tampered-banner";
    DOM.verificationResultBanner.querySelector(".banner-status-title").textContent = "TAMPERED DOCUMENT";
    DOM.verificationResultBanner.querySelector(".banner-status-subtext").textContent = "This PDF's SHA-256 hash was not found on the blockchain. The file content has been altered or never notarized.";
    return;
  }

  // Check 1 Pass: Hash Match OK
  DOM.checkHashMatchRow.className = "check-item pass";
  DOM.checkHashMatchRow.querySelector(".check-bullet").textContent = "✓";
  
  // Show record details
  DOM.fetchedRecordMetadataBox.classList.remove("hidden");
  DOM.metaFileName.textContent = registeredRecord.fileName;
  DOM.metaTimestamp.textContent = new Date(registeredRecord.timestamp * 1000).toLocaleString();
  DOM.metaRegisteredBy.textContent = registeredRecord.registeredBy;
  DOM.metaPublicKey.textContent = registeredRecord.publicKey;
  DOM.metaSignature.textContent = registeredRecord.signature;

  if (!signatureValid) {
    // Check 2 Fail: FORGED DOCUMENT (Hash matches but signature is invalid)
    DOM.checkSignatureValidRow.className = "check-item fail";
    DOM.checkSignatureValidRow.querySelector(".check-bullet").textContent = "✗";
    
    DOM.verificationResultBanner.className = "verification-result-banner forged-banner";
    DOM.verificationResultBanner.querySelector(".banner-status-title").textContent = "FORGED DOCUMENT";
    DOM.verificationResultBanner.querySelector(".banner-status-subtext").textContent = "The document hash exists, but the recorded signature is invalid for this public key. The transaction structure may be forged.";
    return;
  }

  // Both Pass: AUTHENTIC DOCUMENT
  DOM.checkSignatureValidRow.className = "check-item pass";
  DOM.checkSignatureValidRow.querySelector(".check-bullet").textContent = "✓";
  
  DOM.verificationResultBanner.className = "verification-result-banner authentic-banner";
  DOM.verificationResultBanner.querySelector(".banner-status-title").textContent = "AUTHENTIC DOCUMENT";
  DOM.verificationResultBanner.querySelector(".banner-status-subtext").textContent = "Verification succeeded! The document hash matches the immutable ledger record, and the digital signature is valid.";
}

// Execute checks sequence
async function runVerificationProcess(hashHex, overrideSignature = null, overridePublicKey = null) {
  resetVerificationChecklist();
  
  // Step 1: Fetch from Smart Contract
  const record = await fetchRecordByHash(hashHex);
  
  if (!record) {
    renderVerificationResults(hashHex, null, false);
    return;
  }
  
  // Use overrides if manually specified
  const signatureToVerify = overrideSignature || record.signature;
  const publicKeyToVerify = overridePublicKey || record.publicKey;
  
  // Step 2: Validate Cryptographic Signature
  const signatureValid = await verifySignature(publicKeyToVerify, hashHex, signatureToVerify);
  
  renderVerificationResults(hashHex, record, signatureValid);
}

// --- Event Listeners ---

// 1. Keys Tab Event Handlers
DOM.generateKeysBtn.addEventListener("click", async () => {
  try {
    DOM.generateKeysBtn.disabled = true;
    DOM.generateKeysBtn.textContent = "Generating...";
    
    const keyPair = await generateECDSAKeyPair();
    
    // Export PEMs
    const privatePem = await exportPrivateKeyToPem(keyPair.privateKey);
    const publicPem = await exportPublicKeyToPem(keyPair.publicKey);
    
    // Store in memory
    appState.loadedPrivateKey = keyPair.privateKey;
    appState.loadedPublicKey = keyPair.publicKey;
    
    // Display in UI
    DOM.privateKeyPemDisplay.value = privatePem;
    DOM.publicKeyPemDisplay.value = publicPem;
    
    DOM.keypairDisplay.classList.remove("hidden");
    
    updateLoadedKeyUI();
  } catch (error) {
    console.error("Key generation failed:", error);
    alert("Key Generation Failed.");
  } finally {
    DOM.generateKeysBtn.disabled = false;
    DOM.generateKeysBtn.textContent = "Generate ECDSA P-256 Key Pair";
  }
});

DOM.downloadPrivateKeyBtn.addEventListener("click", () => {
  const content = DOM.privateKeyPemDisplay.value;
  if (content) triggerFileDownload("identity_private_key.pem", content);
});

DOM.downloadPublicKeyBtn.addEventListener("click", () => {
  const content = DOM.publicKeyPemDisplay.value;
  if (content) triggerFileDownload("identity_public_key.pem", content);
});

// Import key files dropzone and raw input handlers
DOM.keyFileDropzone.addEventListener("click", () => DOM.privateKeyFileInput.click());

DOM.privateKeyFileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) handleKeyFileRead(file);
});

DOM.keyFileDropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  DOM.keyFileDropzone.classList.add("dragover");
});

DOM.keyFileDropzone.addEventListener("dragleave", () => {
  DOM.keyFileDropzone.classList.remove("dragover");
});

DOM.keyFileDropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  DOM.keyFileDropzone.classList.remove("dragover");
  const file = e.dataTransfer.files[0];
  if (file) handleKeyFileRead(file);
});

function handleKeyFileRead(file) {
  const reader = new FileReader();
  reader.onload = async (e) => {
    const text = e.target.result;
    DOM.privateKeyInputArea.value = text;
    await loadPrivateKeyFromString(text);
  };
  reader.readAsText(file);
}

DOM.loadPastedKeyBtn.addEventListener("click", async () => {
  const text = DOM.privateKeyInputArea.value.trim();
  if (text) {
    await loadPrivateKeyFromString(text);
  } else {
    alert("Please paste a Private Key PEM string first.");
  }
});

async function loadPrivateKeyFromString(pemString) {
  try {
    if (!pemString.includes("-----BEGIN PRIVATE KEY-----")) {
      throw new Error("Invalid PEM format. Missing private key headers.");
    }
    const privKey = await importPrivateKeyFromPem(pemString);
    appState.loadedPrivateKey = privKey;
    
    // Clean public key in-memory since we loaded raw private key
    appState.loadedPublicKey = null;
    
    updateLoadedKeyUI();
    alert("Cryptographic Private Key loaded successfully.");
  } catch (error) {
    console.error("Key import error:", error);
    appState.loadedPrivateKey = null;
    updateLoadedKeyUI();
    alert("Failed to load Private Key: " + error.message);
  }
}

// 2. Sign Tab Event Handlers
DOM.pdfSignDropzone.addEventListener("click", () => DOM.signPdfFileInput.click());

DOM.signPdfFileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) handleSignFileSelected(file);
});

DOM.pdfSignDropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  DOM.pdfSignDropzone.classList.add("dragover");
});

DOM.pdfSignDropzone.addEventListener("dragleave", () => {
  DOM.pdfSignDropzone.classList.remove("dragover");
});

DOM.pdfSignDropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  DOM.pdfSignDropzone.classList.remove("dragover");
  const file = e.dataTransfer.files[0];
  if (file) handleSignFileSelected(file);
});

async function handleSignFileSelected(file) {
  if (file.type !== "application/pdf") {
    alert("Please select a PDF document only.");
    return;
  }
  
  DOM.pdfSignUploadText.textContent = file.name;
  appState.selectedSignFile = file;
  
  // Calculate SHA-256 Hash
  DOM.signFileHash.textContent = "Calculating hash...";
  DOM.pdfHashResultBox.classList.remove("hidden");
  DOM.signFileName.textContent = file.name;
  DOM.signFileSize.textContent = formatBytes(file.size);
  
  try {
    const hash = await hashFile(file);
    appState.selectedSignFileHash = hash;
    DOM.signFileHash.textContent = hash;
    
    // Reset output signature fields
    DOM.signatureResultBox.classList.add("hidden");
    DOM.txReceiptBox.classList.add("hidden");
    
    // Enable button if private key is loaded
    if (appState.loadedPrivateKey) {
      DOM.signDocumentBtn.disabled = false;
    }
  } catch (err) {
    console.error("Error hashing PDF:", err);
    DOM.signFileHash.textContent = "Hashing failed.";
  }
}

DOM.signDocumentBtn.addEventListener("click", async () => {
  if (!appState.loadedPrivateKey || !appState.selectedSignFileHash) return;
  
  try {
    DOM.signDocumentBtn.disabled = true;
    DOM.signDocumentBtn.textContent = "Signing...";
    
    const signatureHex = await signHash(appState.loadedPrivateKey, appState.selectedSignFileHash);
    
    let publicKeyHex = "";
    if (appState.loadedPublicKey) {
      publicKeyHex = await exportPublicKeyToHex(appState.loadedPublicKey);
    } else if (appState.loadedPrivateKey) {
      try {
        const derivedPub = await derivePublicKey(appState.loadedPrivateKey);
        appState.loadedPublicKey = derivedPub;
        publicKeyHex = await exportPublicKeyToHex(derivedPub);
        
        // Also update the UI PEM display so the user has the Derived Public Key visible
        const publicPem = await exportPublicKeyToPem(derivedPub);
        DOM.publicKeyPemDisplay.value = publicPem;
        DOM.keypairDisplay.classList.remove("hidden");
      } catch (err) {
        console.warn("Could not derive public key from private key:", err);
        // Fallback: check DOM display if they pasted/edited it
        const pastedPubPem = DOM.publicKeyPemDisplay.value.trim();
        if (pastedPubPem) {
          try {
            appState.loadedPublicKey = await importPublicKeyFromPem(pastedPubPem);
            publicKeyHex = await exportPublicKeyToHex(appState.loadedPublicKey);
          } catch (e) {
            console.warn("Could not import public key from display:", e);
          }
        }
      }
    }
    
    if (!publicKeyHex) {
      alert("Public key is missing. Please generate a key pair or make sure the Public Key PEM is loaded in the Identity tab.");
      DOM.signDocumentBtn.disabled = false;
      DOM.signDocumentBtn.textContent = "Generate Digital Signature";
      return;
    }
    
    DOM.generatedSignatureHex.value = signatureHex;
    DOM.exportedPublicKeyHex.value = publicKeyHex;
    DOM.signatureResultBox.classList.remove("hidden");
    DOM.txReceiptBox.classList.add("hidden");
  } catch (error) {
    console.error("Signing failed:", error);
    alert("Signing failed: " + error.message);
  } finally {
    DOM.signDocumentBtn.disabled = false;
    DOM.signDocumentBtn.textContent = "Generate Digital Signature";
  }
});

DOM.registerBlockchainBtn.addEventListener("click", async () => {
  const fileName = appState.selectedSignFile.name;
  const docHash = appState.selectedSignFileHash;
  const signature = DOM.generatedSignatureHex.value;
  const publicKey = DOM.exportedPublicKeyHex.value;
  
  if (!fileName || !docHash || !signature || !publicKey) return;
  
  DOM.registerBlockchainBtn.disabled = true;
  DOM.registerBlockchainBtn.textContent = "Mining Block...";
  
  try {
    const receipt = await registerDocumentOnChain(fileName, docHash, signature, publicKey);
    
    // Show Tx success details
    DOM.receiptTxHash.textContent = receipt.transactionHash;
    DOM.receiptBlockNumber.textContent = receipt.blockNumber;
    DOM.txReceiptBox.classList.remove("hidden");
    
    // Trigger ledger count update
    fetchBlockchainStatus();
  } catch (error) {
    console.error("Blockchain registration failed:", error);
  } finally {
    DOM.registerBlockchainBtn.disabled = false;
    DOM.registerBlockchainBtn.textContent = "Publish Notarization to Ethereum (Ganache)";
  }
});

// 3. Ledger Explorer Event Handlers
DOM.refreshLedgerBtn.addEventListener("click", () => {
  fetchLedgerRecords();
});

// 4. Verifier Portal Event Handlers
DOM.pdfVerifyDropzone.addEventListener("click", () => DOM.verifyPdfFileInput.click());

DOM.verifyPdfFileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (file) handleVerifyFileSelected(file);
});

DOM.pdfVerifyDropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  DOM.pdfVerifyDropzone.classList.add("dragover");
});

DOM.pdfVerifyDropzone.addEventListener("dragleave", () => {
  DOM.pdfVerifyDropzone.classList.remove("dragover");
});

DOM.pdfVerifyDropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  DOM.pdfVerifyDropzone.classList.remove("dragover");
  const file = e.dataTransfer.files[0];
  if (file) handleVerifyFileSelected(file);
});

async function handleVerifyFileSelected(file) {
  if (file.type !== "application/pdf") {
    alert("Please select a PDF document only.");
    return;
  }
  
  DOM.pdfVerifyUploadText.textContent = file.name;
  appState.selectedVerifyFile = file;
  
  DOM.verifyFileHash.textContent = "Calculating hash...";
  DOM.verifyFileStatsBox.classList.remove("hidden");
  DOM.verifyFileName.textContent = file.name;
  
  try {
    const hash = await hashFile(file);
    appState.selectedVerifyFileHash = hash;
    DOM.verifyFileHash.textContent = hash;
    
    // Set in manual input override for reference
    DOM.manualVerifyHash.value = hash;
    
    // Execute verification checklist
    await runVerificationProcess(hash);
  } catch (err) {
    console.error("Error hashing PDF:", err);
    DOM.verifyFileHash.textContent = "Hashing failed.";
  }
}

DOM.manualVerifyBtn.addEventListener("click", async () => {
  const hash = DOM.manualVerifyHash.value.trim();
  const signature = DOM.manualVerifySignature.value.trim() || null;
  const publicKey = DOM.manualVerifyPublicKey.value.trim() || null;
  
  if (!hash) {
    alert("Hash is required for manual verification.");
    return;
  }
  
  await runVerificationProcess(hash, signature, publicKey);
});

// Initial startup routine
window.addEventListener("DOMContentLoaded", () => {
  // Check if Web Crypto API is available (Secure Context check)
  const isSecure = window.isSecureContext;
  const hasCrypto = window.crypto && window.crypto.subtle;
  if (!isSecure || !hasCrypto) {
    if (DOM.insecureContextAlert) {
      DOM.insecureContextAlert.classList.remove("hidden");
    }
    console.error("Web Crypto API is not available. Secure Context (HTTPS or localhost) required.");
  }

  fetchBlockchainStatus();
  
  // Refresh status every 15 seconds
  setInterval(fetchBlockchainStatus, 15000);
});
