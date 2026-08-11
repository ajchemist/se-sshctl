import Foundation

public struct SSHKeyCreatedIdentity: Codable, Equatable, Sendable {
    public let label: String
    public let keyType: String
    public let protection: String
    public let ctkPublicKeyHash: String
    public let sshFingerprint: String
    public let publicKey: String

    public init(
        label: String,
        keyType: String,
        protection: String,
        ctkPublicKeyHash: String,
        sshFingerprint: String,
        publicKey: String
    ) {
        self.label = label
        self.keyType = keyType
        self.protection = protection
        self.ctkPublicKeyHash = ctkPublicKeyHash
        self.sshFingerprint = sshFingerprint
        self.publicKey = publicKey
    }
}

public struct SSHKeyCreatedVerification: Codable, Equatable, Sendable {
    public enum Status: String, Codable, Sendable { case passed, failed, notRun = "not-run" }
    public let localSigning: Status

    public init(localSigning: Status) {
        self.localSigning = localSigning
    }
}

public struct SSHKeyCreatedEvent: Codable, Equatable, Sendable {
    public let schemaVersion: Int
    public let eventId: UUID
    public let eventType: String
    public let occurredAt: Date
    public let identity: SSHKeyCreatedIdentity
    public let verification: SSHKeyCreatedVerification

    public init(
        eventId: UUID,
        occurredAt: Date,
        identity: SSHKeyCreatedIdentity,
        verification: SSHKeyCreatedVerification
    ) {
        schemaVersion = 1
        self.eventId = eventId
        eventType = "ssh.key.created"
        self.occurredAt = occurredAt
        self.identity = identity
        self.verification = verification
    }
}

public struct WebhookReceipt: Codable, Equatable, Sendable {
    public let statusCode: Int
    public let deliveredAt: Date

    public init(statusCode: Int, deliveredAt: Date) {
        self.statusCode = statusCode
        self.deliveredAt = deliveredAt
    }
}

public protocol WebhookDelivering: Sendable {
    func deliver(_ event: SSHKeyCreatedEvent) async throws -> WebhookReceipt
}

public struct WebhookOutboxRecord: Codable, Equatable, Sendable {
    public enum FailureCode: String, Codable, Sendable { case transport }

    public let schemaVersion: Int
    public let event: SSHKeyCreatedEvent
    public let attemptCount: Int
    public let lastAttemptAt: Date
    public let failureCode: FailureCode
}

public struct CreationDeliveryOutcome: Codable, Equatable, Sendable {
    public enum Status: String, Codable, Sendable { case succeeded, partialSuccess = "partial-success" }
    public enum WebhookStatus: String, Codable, Sendable { case notConfigured = "not-configured", delivered, pending }

    public let schemaVersion: Int
    public let status: Status
    public let webhook: WebhookStatus
    public let outbox: WebhookOutboxRecord?
}

public struct CreationDeliveryCoordinator: Sendable {
    private let delivery: (any WebhookDelivering)?
    private let now: @Sendable () -> Date

    public init(
        delivery: (any WebhookDelivering)? = nil,
        now: @escaping @Sendable () -> Date = Date.init
    ) {
        self.delivery = delivery
        self.now = now
    }

    public func completeVerifiedCreation(event: SSHKeyCreatedEvent) async -> CreationDeliveryOutcome {
        guard let delivery else {
            return CreationDeliveryOutcome(schemaVersion: 1, status: .succeeded, webhook: .notConfigured, outbox: nil)
        }
        do {
            _ = try await delivery.deliver(event)
            return CreationDeliveryOutcome(schemaVersion: 1, status: .succeeded, webhook: .delivered, outbox: nil)
        } catch {
            return CreationDeliveryOutcome(
                schemaVersion: 1,
                status: .partialSuccess,
                webhook: .pending,
                outbox: WebhookOutboxRecord(
                    schemaVersion: 1,
                    event: event,
                    attemptCount: 1,
                    lastAttemptAt: now(),
                    failureCode: .transport
                )
            )
        }
    }
}
