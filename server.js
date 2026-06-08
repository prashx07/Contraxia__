const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { ethers } = require("ethers");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Security: Use Helmet for secure HTTP headers with custom CSP
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"], // Allow UI interaction script
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        connectSrc: ["'self'", "http://127.0.0.1:8545", "http://127.0.0.1:7545"],
        imgSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

// Security: Rate limiting to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 2000, // Limit each IP to 2000 requests per windowMs (relaxed for polling)
  message: "Too many requests from this IP, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/", limiter);

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Load contract configuration helper
let contract = null;
let provider = null;
let serverSigner = null;

async function initEthers() {
  const configPath = path.resolve(__dirname, "contract_config.json");
  if (!fs.existsSync(configPath)) {
    console.warn("Contract configuration not found. Run deployment script first.");
    return false;
  }

  try {
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    const { address, abi } = config;

    // Connect to Ganache (resilient check on 8545 and 7545)
    let providerUrl = "http://127.0.0.1:8545";
    try {
      provider = new ethers.JsonRpcProvider(providerUrl);
      await provider.getNetwork();
    } catch (e) {
      providerUrl = "http://127.0.0.1:7545";
      provider = new ethers.JsonRpcProvider(providerUrl);
    }

    serverSigner = await provider.getSigner(0);
    contract = new ethers.Contract(address, abi, serverSigner);
    console.log(`Connected to Ganache and contract loaded at: ${address}`);
    return true;
  } catch (error) {
    console.error("Failed to initialize ethers connection:", error.message);
    return false;
  }
}

// Middleware to ensure contract connection is ready
const checkContractConnection = (req, res, next) => {
  if (!contract) {
    return res.status(503).json({
      error: "Smart contract service is unavailable. Please check Ganache and deploy the contract.",
    });
  }
  next();
};

// API: Get Blockchain status
app.get("/api/blockchain/status", async (req, res) => {
  try {
    if (!contract || !provider) {
      const isOk = await initEthers();
      if (!isOk) {
        return res.json({ status: "Disconnected", error: "Not deployed/connected" });
      }
    }
    const blockNumber = await provider.getBlockNumber();
    const network = await provider.getNetwork();
    const address = await contract.getAddress();
    
    // Determine provider connection URL
    let rpcUrl = "http://127.0.0.1:8545";
    if (provider && provider.provider) {
      rpcUrl = provider.providerUrl || rpcUrl;
    } else if (provider && provider._connection) {
      rpcUrl = provider._connection.url || rpcUrl;
    }
    
    return res.json({
      status: "Connected",
      blockHeight: blockNumber,
      chainId: network.chainId.toString(),
      contractAddress: address,
      rpcUrl: rpcUrl,
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch status: " + error.message });
  }
});

// API: Register a document signature
app.post("/api/blockchain/record", checkContractConnection, async (req, res) => {
  try {
    let { docHash, fileName, signature, publicKey } = req.body;

    // --- Input Validation ---
    if (!docHash || !fileName || !signature || !publicKey) {
      return res.status(400).json({ error: "Missing required registration parameters." });
    }

    // Clean inputs
    docHash = docHash.trim().toLowerCase();
    signature = signature.trim().toLowerCase();
    publicKey = publicKey.trim().toLowerCase();
    fileName = String(fileName).trim();

    // Enforce hex check for hash, signature, and public key
    const hexRegex = /^(0x)?[0-9a-fA-F]+$/;
    if (!hexRegex.test(docHash) || !hexRegex.test(signature) || !hexRegex.test(publicKey)) {
      return res.status(400).json({ error: "Hash, signature, and public key must be valid hex strings." });
    }

    // Standardize 0x prefix
    const cleanHash = docHash.startsWith("0x") ? docHash : "0x" + docHash;
    const cleanSignature = signature.startsWith("0x") ? signature : "0x" + signature;
    const cleanPublicKey = publicKey.startsWith("0x") ? publicKey : "0x" + publicKey;

    // Verify Hash is exactly bytes32 (64 hex characters + optional 0x)
    const rawHashHex = cleanHash.slice(2);
    if (rawHashHex.length !== 64) {
      return res.status(400).json({ error: "Invalid hash length. SHA-256 hash must be exactly 32 bytes (64 hex characters)." });
    }

    // Verify Public Key and Signature Sizes
    const publicKeyBuffer = Buffer.from(cleanPublicKey.slice(2), "hex");
    const signatureBuffer = Buffer.from(cleanSignature.slice(2), "hex");

    const MAX_PUBLIC_KEY_BYTES = 65; // ECDSA P-256 public key upper limit
    const MAX_SIGNATURE_BYTES = 72;  // DER-encoded ECDSA signature upper limit

    if (publicKeyBuffer.length > MAX_PUBLIC_KEY_BYTES) {
      return res.status(400).json({
        error: "Public key too large. Use ECDSA P-256, not RSA.",
      });
    }

    if (signatureBuffer.length > MAX_SIGNATURE_BYTES) {
      return res.status(400).json({
        error: "Signature size exceeded. Invalid ECDSA signature.",
      });
    }

    console.log(`Relaying registration for PDF: ${fileName} with Hash: ${cleanHash}`);

    // Pre-flight check: Verify if document is already registered to return 409 Conflict
    try {
      const alreadyExists = await contract.documentExists(cleanHash);
      if (alreadyExists) {
        return res.status(409).json({ error: "This document hash has already been registered on the ledger." });
      }
    } catch (err) {
      return res.status(500).json({ error: "Blockchain pre-flight check failed: " + err.message });
    }

    // Call Solidity smart contract
    const tx = await contract.recordDocument(
      cleanHash,
      fileName,
      cleanSignature,
      cleanPublicKey
    );
    const receipt = await tx.wait();

    return res.json({
      success: true,
      transactionHash: receipt.hash,
      blockNumber: receipt.blockNumber,
      fileName: fileName,
      docHash: cleanHash,
    });
  } catch (error) {
    console.error("Smart contract transaction error:", error);
    return res.status(500).json({ error: "Smart contract execution failed: " + error.message });
  }
});

// API: Get all document records
app.get("/api/blockchain/records", checkContractConnection, async (req, res) => {
  try {
    // 1. Fetch all hashes registered
    const hashes = await contract.getAllDocumentHashes();
    const records = [];

    // 2. Fetch full records sequentially
    for (const hash of hashes) {
      const details = await contract.getDocument(hash);
      records.push({
        docHash: hash,
        fileName: details.fileName,
        signature: details.signature,
        publicKey: details.publicKey,
        timestamp: Number(details.timestamp),
        registeredBy: details.registeredBy,
      });
    }

    return res.json({ count: records.length, records });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch document records: " + error.message });
  }
});

// API: Fetch single document record by hash
app.get("/api/blockchain/record/:hash", checkContractConnection, async (req, res) => {
  try {
    let docHash = req.params.hash.trim().toLowerCase();
    const cleanHash = docHash.startsWith("0x") ? docHash : "0x" + docHash;

    const details = await contract.getDocument(cleanHash);
    return res.json({
      docHash: cleanHash,
      fileName: details.fileName,
      signature: details.signature,
      publicKey: details.publicKey,
      timestamp: Number(details.timestamp),
      registeredBy: details.registeredBy,
    });
  } catch (error) {
    if (error.message.includes("Document not found")) {
      return res.status(404).json({ error: "Document hash not found on the blockchain." });
    }
    return res.status(500).json({ error: "Failed to query document: " + error.message });
  }
});

// Default error handler (no stack traces sent to client)
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.stack);
  res.status(500).json({ error: "An unexpected server error occurred." });
});

// TODO(security): Dev bind to 0.0.0.0 to enable mobile phone network testing.
app.listen(PORT, "0.0.0.0", async () => {
  console.log(`Server listening at http://0.0.0.0:${PORT}`);
  await initEthers();
});
