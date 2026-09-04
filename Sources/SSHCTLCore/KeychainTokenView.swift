import Foundation
import Security

/// The keychain's token access group: the view Apple's `ssh-keychain.dylib`
/// reads CTK identities from. `sc_auth` enumerates the token itself, so the
/// two can disagree — measured on one Mac where the group was empty while
/// `sc_auth` listed three identities (docs/HARDWARE_VERIFICATION.md).
public enum KeychainTokenView {
    /// Identities in the token access group, or nil when the query itself failed
    /// for a reason other than "nothing there".
    public static func identityCount() -> Int? {
        var result: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass: kSecClassIdentity,
            kSecAttrAccessGroup: kSecAttrAccessGroupToken,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnAttributes: true,
        ] as CFDictionary, &result)
        switch status {
        case errSecSuccess: return (result as? [Any])?.count ?? 0
        case errSecItemNotFound: return 0
        default: return nil
        }
    }

    /// Why the provider could not load the identity, when the token view is
    /// short of what `sc_auth` lists; nil when the view is complete and the
    /// provider's own message has to stand.
    public static func shortfall(found: Int?, listed: Int) -> String? {
        guard let found, found < listed else { return nil }
        return """
            the provider reads CTK identities from the keychain's token view, which holds \(found) \
            while sc_auth lists \(listed): this Mac is not publishing its Secure Enclave token to the keychain. \
            Not a session problem: the download fails the same way from the console (Aqua) session and over SSH. \
            Seen on macOS 26.6.1 (Mac16,9); the same download works on 26.6.2 (Mac13,2, MacBookAir10,1). \
            Whether a reboot or the update restores the view is not yet measured. \
            'system_profiler SPSmartCardsDataType' shows the two views side by side under (keychain) and (token).
            """
    }
}
