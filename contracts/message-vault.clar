;; MessageVault - Bitcoin-Anchored Communication Protocol
;;
;; A cryptographic messaging infrastructure that leverages Bitcoin's security
;; through Stacks Layer 2 to provide verifiable, tamper-proof communication
;; records without compromising privacy.
;;
;; Summary:
;; MessageVault enables users to anchor encrypted message hashes on Bitcoin's
;; blockchain via Stacks, creating an immutable audit trail while keeping actual
;; message content private and off-chain. Each communication is cryptographically
;; sealed with SHA-256 hashing and timestamped at the block level, ensuring
;; non-repudiation and proof-of-existence that inherits Bitcoin's finality.
;;
;; Description:
;; This protocol solves the trust problem in digital communications by separating
;; message content from message proof. Users encrypt their messages off-chain and
;; submit only cryptographic hashes to the blockchain, creating verifiable records
;; that can prove a message existed at a specific time without revealing its
;; contents. The system tracks sender-recipient relationships, maintains verification
;; counters for audit purposes, and provides a complete history of message anchoring
;; events. Ideal for legal agreements, compliance documentation, confidential business
;; communications, and any scenario requiring provable message delivery with
;; cryptographic integrity guarantees.
;;
;; Key Features:
;; - Bitcoin-level immutability through Stacks consensus
;; - Zero-knowledge message verification (hashes only, no content exposure)
;; - Tamper-evident audit trails with block-height timestamps
;; - Multi-party verification support with counter tracking
;; - Sender/recipient relationship mapping
;; - Non-repudiation guarantees for digital communications

;; CONSTANTS & ERROR DEFINITIONS

(define-constant CONTRACT-OWNER tx-sender)

;; Error codes for contract operations
(define-constant ERR-UNAUTHORIZED (err u100))
(define-constant ERR-INVALID-MESSAGE (err u101))
(define-constant ERR-MESSAGE-NOT-FOUND (err u102))
(define-constant ERR-INVALID-HASH (err u103))
(define-constant ERR-INVALID-RECIPIENT (err u104))

;; DATA VARIABLES

(define-data-var total-messages uint u0)
(define-data-var contract-version uint u1)

;; DATA MAPS

;; Core message storage: maps message ID to complete metadata
(define-map messages
  { message-id: uint }
  {
    sender: principal,
    recipient: principal,
    message-hash: (buff 32),
    timestamp: uint,
    block-height: uint,
    verified: bool
  }
)

;; User activity tracking: maintains per-user message counts
(define-map user-message-count
  { user: principal }
  { count: uint }
)

;; Hash verification registry: tracks verification events per hash
(define-map message-verification
  { message-hash: (buff 32) }
  { 
    message-id: uint,
    verification-count: uint
  }
)

;; PRIVATE HELPER FUNCTIONS

(define-private (is-valid-hash (hash (buff 32)))
  (> (len hash) u0)
)

(define-private (is-valid-principal (user principal))
  (not (is-eq user 'SP000000000000000000002Q6VF78))
)

(define-private (increment-user-count (user principal))
  (let ((current-count (default-to u0 (get count (map-get? user-message-count { user: user })))))
    (map-set user-message-count 
      { user: user }
      { count: (+ current-count u1) }
    )
  )
)

;; PUBLIC FUNCTIONS - CORE PROTOCOL OPERATIONS

;; @desc Anchors an encrypted message hash to the blockchain with Bitcoin finality
;; @param recipient; Principal address of the intended message recipient
;; @param message-hash; SHA-256 hash of the encrypted message (32 bytes)
;; @returns (response uint uint); Message ID on success, error code on failure
;;
;; Usage: Call this function to create an immutable record of message transmission
;; The hash acts as a cryptographic fingerprint-any tampering invalidates verification
(define-public (send-message (recipient principal) (message-hash (buff 32)))
  (let 
    (
      (message-id (+ (var-get total-messages) u1))
      (current-block stacks-block-height)
    )
    ;; Validate inputs
    (asserts! (is-valid-principal recipient) ERR-INVALID-RECIPIENT)
    (asserts! (is-valid-hash message-hash) ERR-INVALID-HASH)
    (asserts! (not (is-eq tx-sender recipient)) ERR-UNAUTHORIZED)
    
    ;; Anchor message metadata to blockchain
    (map-set messages
      { message-id: message-id }
      {
        sender: tx-sender,
        recipient: recipient,
        message-hash: message-hash,
        timestamp: current-block,
        block-height: current-block,
        verified: false
      }
    )
    
    ;; Initialize verification tracking
    (map-set message-verification
      { message-hash: message-hash }
      {
        message-id: message-id,
        verification-count: u1
      }
    )
    
    ;; Update global state
    (var-set total-messages message-id)
    (increment-user-count tx-sender)
    
    (ok message-id)
  )
)

;; @desc Verifies message authenticity by comparing provided hash against stored record
;; @param message-id; Unique identifier of the message to verify
;; @param provided-hash; Hash to validate against blockchain record
;; @returns (response bool uint); True if hashes match, false otherwise
;;
;; Usage: Recipients or third parties can verify message integrity at any time
;; Successful verification increments the audit counter and marks message as verified
(define-public (verify-message (message-id uint) (provided-hash (buff 32)))
  (let 
    (
      (message-data (unwrap! (map-get? messages { message-id: message-id }) ERR-MESSAGE-NOT-FOUND))
      (stored-hash (get message-hash message-data))
    )
    (asserts! (is-valid-hash provided-hash) ERR-INVALID-HASH)
    (asserts! (> message-id u0) ERR-INVALID-MESSAGE)
    
    (if (is-eq stored-hash provided-hash)
      (begin
        ;; Mark as cryptographically verified
        (map-set messages
          { message-id: message-id }
          (merge message-data { verified: true })
        )
        
        ;; Increment verification audit counter
        (let ((current-verification (default-to { message-id: u0, verification-count: u0 } 
                                               (map-get? message-verification { message-hash: provided-hash }))))
          (map-set message-verification
            { message-hash: provided-hash }
            {
              message-id: message-id,
              verification-count: (+ (get verification-count current-verification) u1)
            }
          )
        )
        (ok true)
      )
      (ok false)
    )
  )
)

;; READ-ONLY FUNCTIONS - QUERY INTERFACE

;; @desc Retrieves complete message record including all metadata
;; @param message-id; Unique message identifier
;; @returns (response (optional message-record) uint); Message data or none
(define-read-only (get-message-info (message-id uint))
  (begin
    (asserts! (> message-id u0) ERR-INVALID-MESSAGE)
    (ok (map-get? messages { message-id: message-id }))
  )
)

;; @desc Returns total messages sent by a specific principal
;; @param user; Principal address to query
;; @returns (response uint uint); Message count for the user
(define-read-only (get-user-message-count (user principal))
  (begin
    (asserts! (is-valid-principal user) ERR-INVALID-RECIPIENT)
    (ok (default-to u0 (get count (map-get? user-message-count { user: user }))))
  )
)

;; @desc Returns global message counter across all users
;; @returns (response uint uint); Total messages processed by protocol
(define-read-only (get-total-messages)
  (ok (var-get total-messages))
)

;; @desc Returns current contract version for compatibility checks
;; @returns (response uint uint); Version number
(define-read-only (get-contract-version)
  (ok (var-get contract-version))
)

;; @desc Checks if a message hash has been registered on-chain
;; @param hash; SHA-256 hash to search for
;; @returns (response bool uint); True if hash exists, false otherwise
(define-read-only (message-hash-exists (hash (buff 32)))
  (begin
    (asserts! (is-valid-hash hash) ERR-INVALID-HASH)
    (ok (is-some (map-get? message-verification { message-hash: hash })))
  )
)

;; @desc Returns number of times a hash has been verified (audit trail)
;; @param hash; Message hash to query
;; @returns (response uint uint); Total verification count
(define-read-only (get-verification-count (hash (buff 32)))
  (begin
    (asserts! (is-valid-hash hash) ERR-INVALID-HASH)
    (ok (default-to u0 (get verification-count (map-get? message-verification { message-hash: hash }))))
  )
)

;; ADMINISTRATIVE FUNCTIONS

;; @desc Updates contract version (restricted to contract owner)
;; @param new-version; Version number to set
;; @returns (response bool uint); Success indicator
(define-public (update-contract-version (new-version uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-UNAUTHORIZED)
    (asserts! (> new-version (var-get contract-version)) ERR-INVALID-MESSAGE)
    (var-set contract-version new-version)
    (ok true)
  )
)
