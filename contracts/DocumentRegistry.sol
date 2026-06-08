// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract DocumentRegistry {

    struct DocumentRecord {
        bytes32 docHash;
        string  fileName;
        bytes   signature;
        bytes   publicKey;    // ECDSA P-256 public key (~65 bytes, NOT RSA)
        uint256 timestamp;
        address registeredBy;
    }

    // Primary lookup: hash → record
    mapping(bytes32 => DocumentRecord) private records;

    // Explicit index array so getAllDocumentHashes() actually works
    bytes32[] private allHashes;

    // Existence check helper — avoids reading a zero-value record
    mapping(bytes32 => bool) private exists;

    event DocumentRegistered(
        bytes32 indexed docHash,
        string fileName,
        address indexed registeredBy,
        uint256 timestamp
    );

    function recordDocument(
        bytes32 _docHash,
        string  memory _fileName,
        bytes   memory _signature,
        bytes   memory _publicKey
    ) external {
        // Guard: revert on duplicates — immutable ledger principle
        require(!exists[_docHash], "Document already registered");

        records[_docHash] = DocumentRecord({
            docHash:      _docHash,
            fileName:     _fileName,
            signature:    _signature,
            publicKey:    _publicKey,
            timestamp:    block.timestamp,
            registeredBy: msg.sender
        });

        allHashes.push(_docHash);   // Keep index in sync
        exists[_docHash] = true;

        emit DocumentRegistered(_docHash, _fileName, msg.sender, block.timestamp);
    }

    function getDocument(bytes32 _docHash)
        external view
        returns (
            string  memory fileName,
            bytes   memory signature,
            bytes   memory publicKey,
            uint256 timestamp,
            address registeredBy
        )
    {
        require(exists[_docHash], "Document not found");
        DocumentRecord storage r = records[_docHash];
        return (r.fileName, r.signature, r.publicKey, r.timestamp, r.registeredBy);
    }

    function getAllDocumentHashes() external view returns (bytes32[] memory) {
        return allHashes;
    }

    function documentExists(bytes32 _docHash) external view returns (bool) {
        return exists[_docHash];
    }
}
