# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

W3C’s ZCAP-LD (Authorization Capabilities for Linked Data) specification defines an object-capability model where authority is granted by possessing a signed “capability” document, rather than by identity or ACLs. A ZCAP-LD capability is a JSON-LD object containing fields like id, invocationTarget, and a cryptographic proof. It can delegate authority by linking to a parent capability (parentCapability) and attaching restrictions called caveats. This model “shifts the burden of identification…to directly work with individuals’ actual capabilities” – in other words, “if you have a valid ‘capability’, you have the authorization” (akin to holding a car key). Our goal is to build a .NET 9 library (for use in-process or via gRPC) that can create, sign, delegate, invoke, and verify ZCAP-LD capabilities for digital wallet agents (using Trinsic for DID/key management). Below are the key requirements and design points.

## Key Requirements and Design

- Data Model (Capabilities): Implement C# classes to represent ZCAP-LD capabilities. A root capability (initial authority) and a delegated capability (child) share common fields. Each capability JSON-LD object should include properties such as id (a URI, e.g. urn:uuid:…), optional parentCapability (URI of parent ZCAP), controller (the DID of the authority issuing it), invocationTarget (the target resource URI), allowedAction (e.g. "read", "write"), optional expires (a timestamp), optional caveat list (restrictions), and a nested proof object. For example, the spec shows a delegated capability JSON with those fields and an @context (e.g. https://w3id.org/zcap/v1). In C#, use properties and JSON serialization attributes ([JsonProperty] etc.) to match these names.

- Linked Data Proofs (Signing): Capabilities must be cryptographically signed using a linked-data proof. Implement code to generate a proof in the style of ZCAP-LD: include fields like type (signature type, e.g. "Ed25519Signature2018" or "Ed25519Signature2020"), created (timestamp), proofPurpose ("capabilityDelegation" when delegating), verificationMethod (the DID key URI), a capabilityChain array, and a signature value (e.g. JWS or base58 string). For a delegation proof, capabilityChain should list the root capability ID and intermediate ancestors (parent fully embedded as object). Use .NET crypto libraries (e.g. System.Security.Cryptography.Ed25519 or RSA) or JSON-LD libraries to canonicalize the capability JSON and produce the signature. The proof format must match the spec examples (e.g. Ed25519Signature2020 with proofValue).

- Capability Delegation (Chains): Support chaining of capabilities. When delegating, build a chain where each delegated capability includes a proof signed by its parent’s controller. The spec requires that the delegation chain is an ordered array: the first element is the root capability’s ID, intermediate ancestors by ID, and the parent capability is embedded and signed. In practice, your code should assemble this chain and include it in the proof. On verification, check each link: ensure each child’s proof is valid using the parent’s public key, and that no chain is too long (limit e.g. 10) to prevent attacks. Store or pass the full chain in invocations so the verifier need not fetch external data.

- Invocation and Verification: Implement invocation processing: when an AI agent invokes an action, it will present the capability and a proof with proofPurpose: "capabilityInvocation". The invocation JSON must include the root capability ID (capability) and requested action (capabilityAction). Verify that the proof’s signature key matches the controller of the root capability and that the requested action is among the capability’s allowedAction. Also check the invocationTarget URI matches (or is a valid prefix of) the capability’s target. According to the spec, the key used to sign must be authorized by the root zcap controller. If valid, allow the action; otherwise deny.

- Caveat Support: Implement handling of caveats (restrictions). The spec notes that each capability may add restrictions via a caveat property, and that child capabilities inherit all caveats of their parents. For example, one could add a time-based caveat (e.g. ValidUntil) or an action-limiting caveat. At minimum, design a Caveat class or interface so common types (timestamp checks, count limits, etc.) can be enforced at invocation time. When verifying a delegated capability, ensure that all caveats from the root through to the leaf are evaluated and honored. (For a minimal implementation, you can start by supporting a simple expiration or true/false caveat and expand later.)

- Digital Identity Integration: Use the Trinsic SDK for DID wallet functionality. In practice, capabilities will be issued by entities (e.g. users or services) with DIDs and keypairs managed by Trinsic. Your code should interface with Trinsic (or any DID library) to fetch a DID document, extract the public key (verificationMethod) for signature verification, or to sign data with a private key. For example, you may call Trinsic APIs to get the public key for a DID used in controller or verificationMethod. In code, this may be abstracted as functions like ResolvePublicKey(did) and SignWithPrivateKey(data, did). (Details depend on the Trinsic SDK’s capabilities.)

- Architecture (In-Process vs gRPC): Since signing uses private keys, implementing this logic in-process (within the same application or service) is simplest. However, you may optionally expose the functionality over gRPC or HTTP for remote agents. For a library, ensure that signing and verification functions are thread-safe and do not persist private keys beyond needed scope. If exposing via gRPC, design service methods like CreateCapability(), DelegateCapability(), VerifyInvocation().

- WASM/Interop Support: (Optional) .NET 8/9 supports building WebAssembly via WASI. The spec use-case hints at cross-environment usage (e.g. Python or JS agents). Consider structuring code for AOT compilation: avoid heavy native dependencies, and test with .NET 9’s wasi-experimental workload. This would allow consuming the library as a Wasm module in other languages. For now, focus on core functionality; WASM/Trinity integration can be added later.

## Project Structure

This is a new .NET project that currently contains:

- `README.md` - Basic project description
- `LICENSE` - MIT License
- No source code or project files yet

## Development Commands

Since this is a new project without .NET project files yet, typical .NET development commands will need to be established once the project structure is created:

- `dotnet new` - Create new .NET projects/solutions
- `dotnet build` - Build the project
- `dotnet test` - Run tests
- `dotnet run` - Run the application
- `dotnet restore` - Restore NuGet packages

## Architecture Notes

The project aims to implement W3C ZCAP-LD specification for .NET 9. Key architectural considerations:

- Target framework: .NET 9
- Purpose: Digital Identity Wallets
- Standards compliance: W3C ZCAP-LD specification

## Development Setup

This project is in its initial state. To begin development:

1. Create appropriate .NET project structure (`dotnet new` commands)
2. Implement ZCAP-LD specification components
3. Add unit tests for verification
4. Consider security best practices for digital identity handling
