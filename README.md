# Contraxia
A Blockchain-Based Smart Contract Verification System Using SHA-256 Hashing, RSA Digital Signatures, and Ethereum Smart Contracts.

# Contraxia

## Blockchain-Based Smart Contract Verification System Using SHA-256, RSA Digital Signatures, and Ethereum

### Overview

Contraxia is a blockchain-powered smart contract verification platform designed to ensure the authenticity, integrity, and security of digital agreements. The system combines cryptographic hashing, RSA public-key cryptography, digital signatures, and Ethereum smart contracts to create a secure and tamper-proof contract management solution.
Unlike traditional contract systems that rely on centralized storage and manual verification, Contraxia provides a decentralized mechanism for verifying contract authenticity and detecting unauthorized modifications.

---

## Problem Statement

Traditional digital contract systems suffer from several challenges:

* Documents can be modified without detection.
* Digital signatures can be difficult to verify.
* Centralized databases are vulnerable to tampering and unauthorized access.
* Verification of contract authenticity often requires intermediaries.
* Lack of transparency and trust between parties.

Contraxia addresses these challenges by leveraging blockchain technology and cryptographic techniques to provide secure contract verification.

---

## Objectives

The primary objectives of Contraxia are:

1. Generate unique SHA-256 hashes for digital contracts.
2. Generate RSA public and private key pairs for users.
3. Digitally sign contract hashes using private keys.
4. Store contract verification data on the Ethereum blockchain.
5. Verify contract authenticity using digital signatures and public keys.
6. Detect contract tampering through hash comparison.
7. Provide a secure and transparent contract verification mechanism.

---

## Features

### Contract Creation

* Create digital contracts through a web interface.
* Generate a unique SHA-256 hash for every contract.

### RSA Key Generation

* Generate RSA 2048-bit public and private key pairs.
* Securely manage cryptographic identities.

### Digital Signature

* Sign contract hashes using RSA private keys.
* Ensure non-repudiation and authenticity.

### Blockchain Storage

* Store contract metadata on Ethereum using smart contracts.
* Maintain immutable records of contract verification data.

### Contract Verification

* Verify digital signatures using public keys.
* Detect tampering by comparing generated and stored hashes.

### Tamper Detection

* Identify any modifications made to a contract after registration.
* Provide instant verification results.

---

## System Architecture

```text
User
 │
 ▼
Create Contract
 │
 ▼
Generate SHA-256 Hash
 │
 ▼
Generate RSA Key Pair
 │
 ▼
Create Digital Signature
 │
 ▼
Store Verification Data
(Ethereum Smart Contract)
 │
 ▼
Verification Module
 │
 ▼
Authentic / Tampered Result
```

---

## Technology Stack

### Frontend

* HTML5
* CSS3
* Bootstrap

### Backend

* Python
* Flask

### Blockchain

* Ethereum
* Solidity
* Ganache

### Cryptography

* SHA-256
* RSA (2048-bit)
* Digital Signatures

### Libraries

* Web3.py
* Cryptography
* Flask
* Py-Solc-X

---

## Project Structure

```text
Contraxia/
│
├── README.md
├── requirements.txt
├── app.py
│
├── blockchain/
│   ├── Contraxia.sol
│   ├── deploy.py
│   ├── abi.json
│   └── contract_info.json
│
├── crypto/
│   ├── hashing.py
│   ├── keys.py
│   └── signature.py
│
├── templates/
│   ├── index.html
│   ├── create.html
│   ├── verify.html
│   └── result.html
│
├── generated_keys/
│
├── uploads/
│
└── static/
```

---

## Workflow

### Contract Registration

1. User enters contract information.
2. System generates a SHA-256 hash.
3. RSA public/private key pair is generated.
4. Contract hash is digitally signed.
5. Hash, signature, and public key are stored on the blockchain.
6. Transaction is recorded on Ethereum.

### Contract Verification

1. User submits a contract for verification.
2. System regenerates the SHA-256 hash.
3. Blockchain record is retrieved.
4. Digital signature is verified using the public key.
5. Hashes are compared.
6. Verification result is displayed.

---

## Installation

### Clone Repository

```bash
git clone https://github.com/prashx07/Contraxia.git
cd Contraxia
```

### Create Virtual Environment

```bash
python -m venv venv
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Start Ganache

Run Ganache locally:

```text
RPC URL:
http://127.0.0.1:7545
```

### Deploy Smart Contract

```bash
python blockchain/deploy.py
```

### Run Application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## Security Mechanisms

### SHA-256 Hashing

Used to generate a unique fingerprint for every contract.

Benefits:

* Collision resistant
* Tamper detection
* Fast verification

### RSA Public-Key Cryptography

Used for:

* Key generation
* Digital signatures
* Identity verification

### Digital Signatures

Provide:

* Authentication
* Integrity
* Non-repudiation

### Blockchain

Provides:

* Immutability
* Transparency
* Decentralized verification
* Trustless storage

---

## Sample Demonstration

### Original Contract

```text
Employee shall work remotely for the company.
```

Generated SHA-256 Hash:

```text
5f6b4f8e2d...
```

Verification Result:

```text
VALID CONTRACT
```

---

### Modified Contract

```text
Employee shall work remotely for the company permanently.
```

Generated SHA-256 Hash:

```text
a91d2e6b1c...
```

Verification Result:

```text
CONTRACT TAMPERED
```

---

## Future Enhancements

* IPFS Integration
* MetaMask Authentication
* Multi-Signature Contracts
* Elliptic Curve Cryptography (ECC)
* QR-Based Verification
* Role-Based Access Control
* Smart Contract Audit Module
* Cloud Deployment

---

## Applications

* Employment Agreements
* Rental Contracts
* Service Agreements
* Academic Certificates
* Legal Documentation
* Government Records
* Supply Chain Contracts

---

## Conclusion

Contraxia demonstrates how blockchain technology and modern cryptographic techniques can be integrated to create a secure smart contract verification platform. By combining SHA-256 hashing, RSA digital signatures, and Ethereum smart contracts, the system ensures document authenticity, integrity, and trust while eliminating dependence on centralized verification authorities.

---

## Author
**Prashant Patwal**
