# Agent & Contributor Instructions

This file provides instructions for AI agents and human contributors working in this codebase.

## Project Overview

W3C's ZCAP-LD (Authorization Capabilities for Linked Data) specification defines an object-capability model where authority is granted by possessing a signed "capability" document, rather than by identity or ACLs. A ZCAP-LD capability is a JSON-LD object containing fields like id, invocationTarget, and a cryptographic proof. It can delegate authority by linking to a parent capability (parentCapability) and attaching restrictions called caveats. This model "shifts the burden of identification…to directly work with individuals' actual capabilities" – in other words, "if you have a valid 'capability', you have the authorization" (akin to holding a car key). Our goal is to build a .NET 10 library (for use in-process or via gRPC) that can create, sign, delegate, invoke, and verify ZCAP-LD capabilities for digital wallet agents (using Trinsic for DID/key management). Below are the key requirements and design points.

## Key Requirements and Design

- Data Model (Capabilities): Implement C# classes to represent ZCAP-LD capabilities. A root capability (initial authority) and a delegated capability (child) share common fields. Each capability JSON-LD object should include properties such as id (a URI, e.g. urn:uuid:…), optional parentCapability (URI of parent ZCAP), controller (the DID of the authority issuing it), invocationTarget (the target resource URI), allowedAction (e.g. "read", "write"), optional expires (a timestamp), optional caveat list (restrictions), and a nested proof object. For example, the spec shows a delegated capability JSON with those fields and an @context (e.g. https://w3id.org/zcap/v1). In C#, use properties and JSON serialization attributes ([JsonProperty] etc.) to match these names.

- Linked Data Proofs (Signing): Capabilities must be cryptographically signed using a linked-data proof. Implement code to generate a proof in the style of ZCAP-LD: include fields like type (signature type, e.g. "Ed25519Signature2018" or "Ed25519Signature2020"), created (timestamp), proofPurpose ("capabilityDelegation" when delegating), verificationMethod (the DID key URI), a capabilityChain array, and a signature value (e.g. JWS or base58 string). For a delegation proof, capabilityChain should list the root capability ID and intermediate ancestors (parent fully embedded as object). Use .NET crypto libraries (e.g. System.Security.Cryptography.Ed25519 or RSA) or JSON-LD libraries to canonicalize the capability JSON and produce the signature. The proof format must match the spec examples (e.g. Ed25519Signature2020 with proofValue).

- Capability Delegation (Chains): Support chaining of capabilities. When delegating, build a chain where each delegated capability includes a proof signed by its parent’s controller. The spec requires that the delegation chain is an ordered array: the first element is the root capability’s ID, intermediate ancestors by ID, and the parent capability is embedded and signed. In practice, your code should assemble this chain and include it in the proof. On verification, check each link: ensure each child’s proof is valid using the parent’s public key, and that no chain is too long (limit e.g. 10) to prevent attacks. Store or pass the full chain in invocations so the verifier need not fetch external data.

- Invocation and Verification: Implement invocation processing: when an AI agent invokes an action, it will present the capability and a proof with proofPurpose: "capabilityInvocation". The invocation JSON must include the root capability ID (capability) and requested action (capabilityAction). Verify that the proof’s signature key matches the controller of the root capability and that the requested action is among the capability’s allowedAction. Also check the invocationTarget URI matches (or is a valid prefix of) the capability’s target. According to the spec, the key used to sign must be authorized by the root zcap controller. If valid, allow the action; otherwise deny.

- Caveat Support: Implement handling of caveats (restrictions). The spec notes that each capability may add restrictions via a caveat property, and that child capabilities inherit all caveats of their parents. For example, one could add a time-based caveat (e.g. ValidUntil) or an action-limiting caveat. At minimum, design a Caveat class or interface so common types (timestamp checks, count limits, etc.) can be enforced at invocation time. When verifying a delegated capability, ensure that all caveats from the root through to the leaf are evaluated and honored. (For a minimal implementation, you can start by supporting a simple expiration or true/false caveat and expand later.)

- Digital Identity Integration: In practice, capabilities will be issued by entities (e.g. users or services) with DIDs and keypairs managed by Trinsic. Your code should plan for implementors to provide their own DID managing library to fetch a DID document, extract the public key (verificationMethod) for signature verification, or to sign data with a private key. For example, you may call Trinsic APIs to get the public key for a DID used in controller or verificationMethod. In code, this may be abstracted as functions like ResolvePublicKey(did) and SignWithPrivateKey(data, did).

- Architecture (In-Process vs gRPC): Since signing uses private keys, implementing this logic in-process (within the same application or service) is simplest. However, you may optionally expose the functionality over gRPC or HTTP for remote agents. For a library, ensure that signing and verification functions are thread-safe and do not persist private keys beyond needed scope. If exposing via gRPC, design service methods like CreateCapability(), DelegateCapability(), VerifyInvocation().

- WASM/Interop Support: (Optional) .NET 10 supports building WebAssembly via WASI. The spec use-case hints at cross-environment usage (e.g. Python or JS agents). Consider structuring code for AOT compilation: avoid heavy native dependencies, and test with .NET 10's wasi-experimental workload. This would allow consuming the library as a Wasm module in other languages. For now, focus on core functionality; WASM/Trinity integration can be added later.

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

The project aims to implement W3C ZCAP-LD specification for .NET 10. Key architectural considerations:

- Target framework: .NET 10
- Purpose: Digital Identity Wallets
- Standards compliance: W3C ZCAP-LD specification

## Workflow Orchestration

### 1. Plan Mode Fault

- Enter plan mode for ANY non-trivial task defined as a task that takes 3 steps or more or that requires architectural decisions.
- If something goes sideways, STOP and re-plan immediately - don't keep pushing
- Use plan mode for verification steps, not just building
- Write detailed specs upfront to reduce ambiguity

### 2. Subagent Strategy

- Use subagents liberally to keep main context window clean
- Offload research, exploration, and parallel analysis to subagents
- For complex problems, throw more compute at it via subagents
- One task per subagent for focused execution

### 3. Self-Improvement Loop

- After ANY correction from the user: update `tasks/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake
- Ruthlessly iterate on these lessons until mistake rate drops
- Review lessons at session start for relevant project

### 4. Verification Before Done

- Never mark a task complete without proving it works
- Diff behavior between main and your changes when relevant
- Ask yourself: "Would a staff engineer approve this,"
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)

- For non-trivial changes: pause and ask "is there a more elegant way?"
- If a fix feels hacky: "Knowing everything I know now, implement the elegant solution"
- Skip this for simple, obvious fixes - don't over-engineer
- Challenge your own work before presenting it

### 6. Autonomous Bug Fixing

- When given a bug report: just fix it. Don't ask for hand-holding
- Point at logs, errors, failing tests - then resolve them
- Zero context switching required from the user
- Go fix failing CI tests without being told how

# Task Management

1. **Plan First**: Write plan to `tasks/todo{timestamp}.md` with checkable items
2. **Verify Plan**: Check in before starting implementation
3. **Track Progress**: Mark items complete as you go
4. **Explain Changes**: High-level summary at each step
5. **Document Results**: Add review section to 'tasks/todo.m,
6. **Capture Lessons**: Update 'tasks/lessons.md' after corrections

## Core Principles

- **Simplicity First**: Make every change as simple as possible. Impact minimal code.
- **No Laziness**: Find root causes. No temporary fixes. Staff Engineer standards.
- **Minimal Impact**: Changes should only touch what's necessary. Avoid introducing bugs.
