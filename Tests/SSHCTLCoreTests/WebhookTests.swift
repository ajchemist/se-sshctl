import Foundation
import Testing
@testable import SSHCTLCore

@Test func keyCreatedEventHasDeterministicV1JSONWithoutSensitiveFields() throws {
    let json = try JSONOutput.encode(sampleEvent)

    #expect(json == #"{"eventId":"00000000-0000-0000-0000-000000000001","eventType":"ssh.key.created","identity":{"ctkPublicKeyHash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","keyType":"p-256-ne","label":"example","protection":"none","publicKey":"sk-ecdsa-sha2-nistp256@openssh.com AAAATEST example","sshFingerprint":"SHA256:test"},"occurredAt":"1970-01-01T00:00:00Z","schemaVersion":1,"verification":{"localSigning":"passed"}}"#)
    #expect(!json.lowercased().contains("private"))
    #expect(!json.lowercased().contains("wrapper"))
    #expect(!json.lowercased().contains("keychain"))
}

@Test func failedWebhookBecomesExplicitPartialSuccessOutbox() async {
    let sink = MockWebhook(result: .failure(MockFailure.failed))
    let coordinator = CreationDeliveryCoordinator(delivery: sink, now: { Date(timeIntervalSince1970: 1) })

    let outcome = await coordinator.completeVerifiedCreation(event: sampleEvent)

    #expect(outcome.status == .partialSuccess)
    #expect(outcome.webhook == .pending)
    #expect(outcome.outbox?.event == sampleEvent)
    #expect(outcome.outbox?.attemptCount == 1)
    #expect(outcome.outbox?.failureCode == .transport)
    #expect(await sink.deliveredEvents() == [sampleEvent])
}

@Test func mockWebhookSuccessNeedsNoOutbox() async {
    let receipt = WebhookReceipt(statusCode: 202, deliveredAt: Date(timeIntervalSince1970: 2))
    let sink = MockWebhook(result: .success(receipt))

    let outcome = await CreationDeliveryCoordinator(delivery: sink).completeVerifiedCreation(event: sampleEvent)

    #expect(outcome.status == .succeeded)
    #expect(outcome.webhook == .delivered)
    #expect(outcome.outbox == nil)
}

private let sampleEvent = SSHKeyCreatedEvent(
    eventId: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!,
    occurredAt: Date(timeIntervalSince1970: 0),
    identity: SSHKeyCreatedIdentity(
        label: "example",
        keyType: "p-256-ne",
        protection: "none",
        ctkPublicKeyHash: String(repeating: "A", count: 64),
        sshFingerprint: "SHA256:test",
        publicKey: "sk-ecdsa-sha2-nistp256@openssh.com AAAATEST example"
    ),
    verification: SSHKeyCreatedVerification(localSigning: .passed)
)

private enum MockFailure: Error {
    case failed
}

private actor MockWebhook: WebhookDelivering {
    private let result: Result<WebhookReceipt, Error>
    private var events: [SSHKeyCreatedEvent] = []

    init(result: Result<WebhookReceipt, Error>) {
        self.result = result
    }

    func deliver(_ event: SSHKeyCreatedEvent) async throws -> WebhookReceipt {
        events.append(event)
        return try result.get()
    }

    func deliveredEvents() -> [SSHKeyCreatedEvent] { events }
}
