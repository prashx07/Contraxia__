// scripts/deploy.js
const { ethers } = require("ethers");
const solc = require("solc");
const fs = require("fs");
const path = require("path");

async function main() {
    const sourcePath = path.resolve(__dirname, "../contracts/DocumentRegistry.sol");
    if (!fs.existsSync(sourcePath)) {
        console.error("Solidity source file not found at:", sourcePath);
        process.exit(1);
    }
    const source = fs.readFileSync(sourcePath, "utf8");

    // solc input format must match pragma version — use 0.8.19
    const input = {
        language: "Solidity",
        sources: { "DocumentRegistry.sol": { content: source } },
        settings: { outputSelection: { "*": { "*": ["abi", "evm.bytecode"] } } }
    };

    console.log("Compiling DocumentRegistry.sol...");
    const output = JSON.parse(solc.compile(JSON.stringify(input)));

    // Always check for compilation errors before deploying
    if (output.errors) {
        output.errors.forEach(e => console.error(e.formattedMessage));
        if (output.errors.some(e => e.severity === "error")) {
            console.error("Compilation failed.");
            process.exit(1);
        }
    }

    const contract = output.contracts["DocumentRegistry.sol"]["DocumentRegistry"];
    const abi      = contract.abi;
    const bytecode = contract.evm.bytecode.object;

    // Connect to Ganache
    // Check ports 8545 and 7545 to be resilient
    let providerUrl = "http://127.0.0.1:8545";
    console.log("Connecting to Ganache at " + providerUrl + "...");
    
    let provider;
    try {
        provider = new ethers.JsonRpcProvider(providerUrl);
        await provider.getNetwork();
    } catch (err) {
        console.warn("Ganache not found on 8545. Trying port 7545...");
        providerUrl = "http://127.0.0.1:7545";
        provider = new ethers.JsonRpcProvider(providerUrl);
    }

    const signer = await provider.getSigner(0); // First pre-funded Ganache account
    const deployerAddress = await signer.getAddress();
    console.log("Deploying contract from account:", deployerAddress);

    const factory  = new ethers.ContractFactory(abi, bytecode, signer);
    const deployed = await factory.deploy();
    await deployed.waitForDeployment();

    const address = await deployed.getAddress();
    console.log("Contract deployed successfully at:", address);

    // Write config for server.js and frontend to consume
    fs.writeFileSync(
        path.resolve(__dirname, "../contract_config.json"),
        JSON.stringify({ address, abi }, null, 2)
    );
    console.log("Contract config written to contract_config.json");
}

main().catch(console.error);
