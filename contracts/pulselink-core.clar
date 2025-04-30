;; pulselink-core
;; 
;; This smart contract serves as the central hub for the PulseLink health data aggregation platform.
;; It manages user profiles, device connections, data access permissions, and sharing capabilities,
;; allowing users to maintain sovereignty over their health data while enabling secure, permissioned
;; sharing with healthcare providers, researchers, and fitness coaches.
;; 
;; The contract implements a comprehensive permission system with granular access controls and
;; maintains an immutable audit trail of all data access events while keeping the actual health
;; data encrypted and stored off-chain.

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-USER-ALREADY-EXISTS (err u101))
(define-constant ERR-USER-NOT-FOUND (err u102))
(define-constant ERR-DEVICE-ALREADY-REGISTERED (err u103))
(define-constant ERR-DEVICE-NOT-FOUND (err u104))
(define-constant ERR-INVALID-ACCESS-TYPE (err u105))
(define-constant ERR-ACCESS-ALREADY-GRANTED (err u106))
(define-constant ERR-ACCESS-NOT-FOUND (err u107))
(define-constant ERR-INVALID-EXPIRY (err u108))
(define-constant ERR-ACCESS-EXPIRED (err u109))
(define-constant ERR-INVALID-DATA-CATEGORY (err u110))

;; Data categories
(define-constant DATA-CATEGORY-HEART-RATE u1)
(define-constant DATA-CATEGORY-SLEEP u2)
(define-constant DATA-CATEGORY-ACTIVITY u3)
(define-constant DATA-CATEGORY-BLOOD-PRESSURE u4)
(define-constant DATA-CATEGORY-BLOOD-GLUCOSE u5)
(define-constant DATA-CATEGORY-WEIGHT u6)
(define-constant DATA-CATEGORY-TEMPERATURE u7)
(define-constant DATA-CATEGORY-OXYGEN-SATURATION u8)
(define-constant DATA-CATEGORY-ALL u99)

;; Access types
(define-constant ACCESS-TYPE-READ u1)
(define-constant ACCESS-TYPE-WRITE u2)
(define-constant ACCESS-TYPE-READ-WRITE u3)

;; Data maps

;; Stores user profile information
(define-map users
  { user: principal }
  {
    name: (string-utf8 100),
    email: (string-utf8 100),
    created-at: uint,
    updated-at: uint,
    active: bool
  }
)

;; Tracks registered devices for each user
(define-map user-devices
  { user: principal, device-id: (string-utf8 50) }
  {
    device-name: (string-utf8 100),
    device-type: (string-utf8 50),
    registered-at: uint,
    last-sync: uint,
    active: bool
  }
)

;; Maps users to their devices for easy lookup
(define-map user-to-devices
  { user: principal }
  { device-ids: (list 20 (string-utf8 50)) }
)

;; Manages access permissions granted by users
(define-map access-permissions
  { owner: principal, accessor: principal, data-category: uint }
  {
    access-type: uint,
    granted-at: uint,
    expires-at: uint,
    revoked: bool
  }
)

;; Tracks all data access events
(define-map access-logs
  { access-id: uint }
  {
    owner: principal,
    accessor: principal,
    data-category: uint,
    timestamp: uint,
    purpose: (string-utf8 200)
  }
)

;; Counter for access log IDs
(define-data-var access-log-counter uint u0)

;; Private functions

;; Helper function to validate data category
(define-private (valid-data-category? (category uint))
  (or
    (is-eq category DATA-CATEGORY-HEART-RATE)
    (is-eq category DATA-CATEGORY-SLEEP)
    (is-eq category DATA-CATEGORY-ACTIVITY)
    (is-eq category DATA-CATEGORY-BLOOD-PRESSURE)
    (is-eq category DATA-CATEGORY-BLOOD-GLUCOSE)
    (is-eq category DATA-CATEGORY-WEIGHT)
    (is-eq category DATA-CATEGORY-TEMPERATURE)
    (is-eq category DATA-CATEGORY-OXYGEN-SATURATION)
    (is-eq category DATA-CATEGORY-ALL)
  )
)

;; Helper function to validate access type
(define-private (valid-access-type? (access-type uint))
  (or
    (is-eq access-type ACCESS-TYPE-READ)
    (is-eq access-type ACCESS-TYPE-WRITE)
    (is-eq access-type ACCESS-TYPE-READ-WRITE)
  )
)

;; Helper function to check if a user exists
(define-private (user-exists? (user principal))
  (default-to false (get active (map-get? users { user: user })))
)

;; Helper function to check if caller is authorized for a user
(define-private (is-authorized (user principal))
  (is-eq tx-sender user)
)

;; Helper function to add device to user's device list
(define-private (add-device-to-list (user principal) (device-id (string-utf8 50)))
  (let
    (
      (current-devices (default-to { device-ids: (list) } (map-get? user-to-devices { user: user })))
      (updated-devices (unwrap-panic (as-max-len? (append (get device-ids current-devices) device-id) u20)))
    )
    (map-set user-to-devices { user: user } { device-ids: updated-devices })
  )
)

;; Helper function to log access event
(define-private (log-access-event (owner principal) (accessor principal) (data-category uint) (purpose (string-utf8 200)))
  (let
    (
      (current-id (var-get access-log-counter))
      (next-id (+ current-id u1))
    )
    (var-set access-log-counter next-id)
    (map-set access-logs
      { access-id: current-id }
      {
        owner: owner,
        accessor: accessor,
        data-category: data-category,
        timestamp: block-height,
        purpose: purpose
      }
    )
    (ok current-id)
  )
)

;; Helper function to check if access permission is valid and not expired
(define-private (has-valid-access? (owner principal) (accessor principal) (data-category uint))
  (match (map-get? access-permissions { owner: owner, accessor: accessor, data-category: data-category })
    permission 
      (and 
        (not (get revoked permission))
        (or
          (is-eq (get expires-at permission) u0) ;; no expiration
          (> (get expires-at permission) block-height)
        )
      )
    false
  )
)

;; Read-only functions

;; Get user profile
(define-read-only (get-user-profile (user principal))
  (map-get? users { user: user })
)

;; Get user devices
(define-read-only (get-user-devices (user principal))
  (map-get? user-to-devices { user: user })
)

;; Get device details
(define-read-only (get-device-details (user principal) (device-id (string-utf8 50)))
  (map-get? user-devices { user: user, device-id: device-id })
)

;; Check if user has granted access to accessor for a specific data category
(define-read-only (check-access-permission (owner principal) (accessor principal) (data-category uint))
  (if (valid-data-category? data-category)
    (if (has-valid-access? owner accessor data-category)
      (ok true)
      (if (has-valid-access? owner accessor DATA-CATEGORY-ALL)
        (ok true)
        (err ERR-ACCESS-NOT-FOUND)
      )
    )
    (err ERR-INVALID-DATA-CATEGORY)
  )
)

;; Get access permission details
(define-read-only (get-access-permission (owner principal) (accessor principal) (data-category uint))
  (map-get? access-permissions { owner: owner, accessor: accessor, data-category: data-category })
)

;; Get access log by ID
(define-read-only (get-access-log (access-id uint))
  (map-get? access-logs { access-id: access-id })
)

;; Public functions

;; Register a new user
(define-public (register-user (name (string-utf8 100)) (email (string-utf8 100)))
  (let
    (
      (user tx-sender)
      (current-time block-height)
    )
    (if (user-exists? user)
      ERR-USER-ALREADY-EXISTS
      (begin
        (map-set users
          { user: user }
          {
            name: name,
            email: email,
            created-at: current-time,
            updated-at: current-time,
            active: true
          }
        )
        (map-set user-to-devices { user: user } { device-ids: (list) })
        (ok true)
      )
    )
  )
)

;; Update user profile
(define-public (update-user-profile (name (string-utf8 100)) (email (string-utf8 100)))
  (let
    (
      (user tx-sender)
      (current-time block-height)
    )
    (if (not (user-exists? user))
      ERR-USER-NOT-FOUND
      (match (map-get? users { user: user })
        existing-profile
          (begin
            (map-set users
              { user: user }
              {
                name: name,
                email: email,
                created-at: (get created-at existing-profile),
                updated-at: current-time,
                active: true
              }
            )
            (ok true)
          )
        ERR-USER-NOT-FOUND
      )
    )
  )
)

;; Deactivate user profile
(define-public (deactivate-user)
  (let
    (
      (user tx-sender)
    )
    (if (not (user-exists? user))
      ERR-USER-NOT-FOUND
      (match (map-get? users { user: user })
        existing-profile
          (begin
            (map-set users
              { user: user }
              {
                name: (get name existing-profile),
                email: (get email existing-profile),
                created-at: (get created-at existing-profile),
                updated-at: block-height,
                active: false
              }
            )
            (ok true)
          )
        ERR-USER-NOT-FOUND
      )
    )
  )
)

;; Register a device for a user
(define-public (register-device (device-id (string-utf8 50)) (device-name (string-utf8 100)) (device-type (string-utf8 50)))
  (let
    (
      (user tx-sender)
      (current-time block-height)
    )
    (if (not (user-exists? user))
      ERR-USER-NOT-FOUND
      (if (is-some (map-get? user-devices { user: user, device-id: device-id }))
        ERR-DEVICE-ALREADY-REGISTERED
        (begin
          (map-set user-devices
            { user: user, device-id: device-id }
            {
              device-name: device-name,
              device-type: device-type,
              registered-at: current-time,
              last-sync: u0,
              active: true
            }
          )
          (add-device-to-list user device-id)
          (ok true)
        )
      )
    )
  )
)

;; Update device sync time
(define-public (update-device-sync (device-id (string-utf8 50)))
  (let
    (
      (user tx-sender)
    )
    (if (not (user-exists? user))
      ERR-USER-NOT-FOUND
      (match (map-get? user-devices { user: user, device-id: device-id })
        device
          (begin
            (map-set user-devices
              { user: user, device-id: device-id }
              {
                device-name: (get device-name device),
                device-type: (get device-type device),
                registered-at: (get registered-at device),
                last-sync: block-height,
                active: (get active device)
              }
            )
            (ok true)
          )
        ERR-DEVICE-NOT-FOUND
      )
    )
  )
)

;; Deactivate a device
(define-public (deactivate-device (device-id (string-utf8 50)))
  (let
    (
      (user tx-sender)
    )
    (if (not (user-exists? user))
      ERR-USER-NOT-FOUND
      (match (map-get? user-devices { user: user, device-id: device-id })
        device
          (begin
            (map-set user-devices
              { user: user, device-id: device-id }
              {
                device-name: (get device-name device),
                device-type: (get device-type device),
                registered-at: (get registered-at device),
                last-sync: (get last-sync device),
                active: false
              }
            )
            (ok true)
          )
        ERR-DEVICE-NOT-FOUND
      )
    )
  )
)

;; Grant access to health data
(define-public (grant-access (accessor principal) (data-category uint) (access-type uint) (expires-at uint))
  (let
    (
      (owner tx-sender)
      (current-time block-height)
    )
    (if (not (user-exists? owner))
      ERR-USER-NOT-FOUND
      (if (not (valid-data-category? data-category))
        ERR-INVALID-DATA-CATEGORY
        (if (not (valid-access-type? access-type))
          ERR-INVALID-ACCESS-TYPE
          (if (and (> expires-at u0) (<= expires-at current-time))
            ERR-INVALID-EXPIRY
            (if (has-valid-access? owner accessor data-category)
              ERR-ACCESS-ALREADY-GRANTED
              (begin
                (map-set access-permissions
                  { owner: owner, accessor: accessor, data-category: data-category }
                  {
                    access-type: access-type,
                    granted-at: current-time,
                    expires-at: expires-at,
                    revoked: false
                  }
                )
                (ok true)
              )
            )
          )
        )
      )
    )
  )
)

;; Revoke access
(define-public (revoke-access (accessor principal) (data-category uint))
  (let
    (
      (owner tx-sender)
    )
    (if (not (user-exists? owner))
      ERR-USER-NOT-FOUND
      (if (not (valid-data-category? data-category))
        ERR-INVALID-DATA-CATEGORY
        (match (map-get? access-permissions { owner: owner, accessor: accessor, data-category: data-category })
          permission
            (begin
              (map-set access-permissions
                { owner: owner, accessor: accessor, data-category: data-category }
                {
                  access-type: (get access-type permission),
                  granted-at: (get granted-at permission),
                  expires-at: (get expires-at permission),
                  revoked: true
                }
              )
              (ok true)
            )
          ERR-ACCESS-NOT-FOUND
        )
      )
    )
  )
)

;; Request access to data (called by accessor, creates a log entry)
(define-public (request-data-access (owner principal) (data-category uint) (purpose (string-utf8 200)))
  (let
    (
      (accessor tx-sender)
    )
    (if (not (user-exists? owner))
      ERR-USER-NOT-FOUND
      (if (not (valid-data-category? data-category))
        ERR-INVALID-DATA-CATEGORY
        (if (has-valid-access? owner accessor data-category)
          (log-access-event owner accessor data-category purpose)
          (if (has-valid-access? owner accessor DATA-CATEGORY-ALL)
            (log-access-event owner accessor data-category purpose)
            ERR-ACCESS-NOT-FOUND
          )
        )
      )
    )
  )
)

;; Update access expiry
(define-public (update-access-expiry (accessor principal) (data-category uint) (new-expiry uint))
  (let
    (
      (owner tx-sender)
      (current-time block-height)
    )
    (if (not (user-exists? owner))
      ERR-USER-NOT-FOUND
      (if (not (valid-data-category? data-category))
        ERR-INVALID-DATA-CATEGORY
        (if (and (> new-expiry u0) (<= new-expiry current-time))
          ERR-INVALID-EXPIRY
          (match (map-get? access-permissions { owner: owner, accessor: accessor, data-category: data-category })
            permission
              (if (get revoked permission)
                ERR-ACCESS-NOT-FOUND
                (begin
                  (map-set access-permissions
                    { owner: owner, accessor: accessor, data-category: data-category }
                    {
                      access-type: (get access-type permission),
                      granted-at: (get granted-at permission),
                      expires-at: new-expiry,
                      revoked: false
                    }
                  )
                  (ok true)
                )
              )
            ERR-ACCESS-NOT-FOUND
          )
        )
      )
    )
  )
)