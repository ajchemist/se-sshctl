import Foundation
import Testing
@testable import SSHCTLCore

@Test func parserReturnsNoIdentitiesForHeaderOnlyFixture() throws {
    #expect(try CTKIdentityParser().parse(fixture("identities-empty")) == [])
}

@Test func parserPreservesLabelsInsteadOfSplittingOnWhitespace() throws {
    let identities = try CTKIdentityParser().parse(fixture("identities-multiple"))

    #expect(identities.count == 3)
    #expect(identities[0].label == "deploy key 東京")
    #expect(identities[1].label == "deploy key 東京")
    #expect(identities[2].label == "prod $(touch nope)")
    #expect(identities[0].ctkPublicKeyHash == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    #expect(identities[0].protection == "none")
    #expect(identities[0].certificateValid == true)
    #expect(identities[2].certificateValid == false)
}

@Test func parserRejectsChangedOrLocalizedHeaders() {
    #expect(throws: CTKIdentityParseError.self) {
        try CTKIdentityParser().parse("키 종류 공개 키 해시 보호 라벨 유효\n")
    }
}

@Test func parserRejectsMalformedOrExtraColumns() {
    let fixture = """
    Key Type  Public Key Hash                                                   Prot  Label                   Common Name             Email Address             Valid To          Valid
    p-256-ne  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA  none  label                   name                                            2030-01-01 00:00  YES EXTRA
    """
    #expect(throws: CTKIdentityParseError.self) {
        try CTKIdentityParser().parse(fixture)
    }
}

@Test func parserPreservesNativeHashTypeAndEncodingFormats() throws {
    let formats: [(CTKIdentityHashType, CTKIdentityHashEncoding, String)] = [
        (.sha1, .hex, String(repeating: "A", count: 40)),
        (.sha1, .b64, String(repeating: "A", count: 27) + "="),
        (.sha256, .hex, String(repeating: "A", count: 64)),
        (.sha256, .b64, String(repeating: "A", count: 43) + "="),
        (.ssh, .hex, String(repeating: "A", count: 64)),
        (.ssh, .b64, "SHA256:" + String(repeating: "A", count: 43)),
    ]

    for (type, encoding, hash) in formats {
        let identities = try CTKIdentityParser(hashType: type, hashEncoding: encoding)
            .parse(fixtureWithHash(hash))
        #expect(identities[0].ctkPublicKeyHash == hash)
    }
}

private func fixture(_ name: String) -> String {
    let url = Bundle.module.url(forResource: name, withExtension: "txt", subdirectory: "Fixtures")!
    return try! String(contentsOf: url, encoding: .utf8)
}

private func fixtureWithHash(_ hash: String) -> String {
    let lines = fixture("identities-multiple").split(whereSeparator: \Character.isNewline)
    let row = String(lines[1]).replacingOccurrences(
        of: String(repeating: "A", count: 64),
        with: hash + String(repeating: " ", count: 64 - hash.count)
    )
    return String(lines[0]) + "\n" + row + "\n"
}
