# MessageVault

**Bitcoin-Anchored Communication Protocol**

---

## Overview

**MessageVault** is a cryptographic messaging protocol that anchors verifiable communication proofs to the Bitcoin blockchain through the **Stacks Layer 2**. It provides **tamper-evident, timestamped, and privacy-preserving** message records — ensuring that digital communications can be proven to exist at a specific time without revealing their content.

This protocol is ideal for **legal correspondence**, **compliance documentation**, **business contracts**, and **audit-sensitive communications** where **non-repudiation**, **integrity**, and **verifiability** are paramount.

---

## Core Principles

* **Bitcoin-Level Immutability:**
  All message proofs are anchored to Bitcoin via Stacks consensus, inheriting Bitcoin’s finality and resistance to tampering.

* **Privacy-Preserving Design:**
  Only message hashes are stored on-chain. Encrypted message contents remain off-chain, preserving confidentiality.

* **Verifiable Proof of Existence:**
  Every message record contains a SHA-256 hash, timestamp, and block height to guarantee authenticity and prevent repudiation.

* **Zero-Knowledge Verification:**
  Verification of messages can occur without revealing message content — only matching hashes are compared.

---

## System Overview

MessageVault separates message *content* from message *proof*.
Users interact with the protocol as follows:

1. **Encrypt Message Off-Chain:**
   The sender encrypts their message using their preferred encryption scheme.

2. **Hash Generation:**
   The encrypted message is hashed using SHA-256 to produce a unique 32-byte fingerprint.

3. **On-Chain Anchoring:**
   The sender calls `send-message`, providing the recipient’s principal and the message hash.
   The protocol stores:

   * Sender and recipient principals
   * Message hash
   * Timestamp and block height
   * Verification status

4. **Verification:**
   Any party can later verify the authenticity of the message by submitting the original encrypted message’s hash via `verify-message`.
   If the hash matches the stored record, the protocol confirms authenticity and increments an audit counter.

---

## Contract Architecture

### Data Variables

| Variable           | Type   | Description                                      |
| ------------------ | ------ | ------------------------------------------------ |
| `total-messages`   | `uint` | Global counter tracking all messages sent        |
| `contract-version` | `uint` | Contract version identifier for upgrade tracking |

### Data Maps

| Map                    | Key                           | Value                                                                    | Description                                    |
| ---------------------- | ----------------------------- | ------------------------------------------------------------------------ | ---------------------------------------------- |
| `messages`             | `{ message-id: uint }`        | `{ sender, recipient, message-hash, timestamp, block-height, verified }` | Core message metadata                          |
| `user-message-count`   | `{ user: principal }`         | `{ count: uint }`                                                        | Tracks messages sent by each user              |
| `message-verification` | `{ message-hash: (buff 32) }` | `{ message-id: uint, verification-count: uint }`                         | Tracks verification frequency per message hash |

---

## Core Functions

### 1. `send-message`

**Anchors a message hash on-chain.**

**Parameters:**

* `recipient` — Principal of the intended recipient
* `message-hash` — 32-byte SHA-256 hash of encrypted message

**Returns:**
`(ok message-id)` on success

**Validation:**

* Ensures recipient is valid and not the sender
* Hash must be a non-empty 32-byte buffer

**Effects:**

* Increments global and per-user counters
* Initializes verification tracking

---

### 2. `verify-message`

**Validates message authenticity using hash comparison.**

**Parameters:**

* `message-id` — Unique ID of the message
* `provided-hash` — Hash to compare

**Returns:**
`(ok true)` if match is successful, `(ok false)` otherwise

**Effects:**

* Marks message as verified
* Increments audit verification count

---

### 3. `get-message-info`

Retrieves the complete metadata for a specific message ID.

### 4. `get-user-message-count`

Returns the total number of messages sent by a user.

### 5. `get-total-messages`

Returns the total messages recorded by the contract.

### 6. `message-hash-exists`

Checks if a message hash has been anchored on-chain.

### 7. `get-verification-count`

Returns the number of times a message hash has been verified.

### 8. `update-contract-version`

Allows the contract owner to update the version, enforcing upgrade integrity.

---

## Data Flow

```
[Sender] 
   │
   │  Encrypt + Hash (off-chain)
   ▼
[send-message()]
   │
   ├── Validate inputs (recipient, hash)
   ├── Record metadata on-chain
   ├── Increment message counters
   ▼
 Blockchain (Stacks Layer 2, anchored to Bitcoin)
   │
   ▼
[Verifier]
   │
   │  Submit hash via verify-message()
   ▼
[Verification]
   ├── Compare stored hash
   ├── Increment verification counter
   └── Confirm authenticity
```

---

## Security Considerations

* **Non-repudiation:**
  Once anchored, the existence of a message hash cannot be denied.

* **Tamper Detection:**
  Any modification to the message invalidates the hash match.

* **Privacy by Design:**
  No message content is ever exposed or stored on-chain.

* **Immutable Audit Trail:**
  Each message and verification event is permanently recorded with a Bitcoin-backed timestamp.

---

## Deployment & Upgrade

* **Owner-Controlled Versioning:**
  Only the contract owner (`CONTRACT-OWNER`) can update `contract-version`.
  New versions must have a higher numeric identifier.

* **Compatibility:**
  Future upgrades should maintain data map schema to ensure continuity of records.

---

## Future Enhancements

* **Multi-Signature Message Attestation**
* **Encrypted Metadata Storage (e.g., via Gaia or IPFS)**
* **Cross-Protocol Integration with Proof-of-Signature systems**
* **Extended Zero-Knowledge Proof support for content validation**

---

## License

MessageVault is released under the **MIT License**.
Use, modify, and extend freely in accordance with open-source standards.
