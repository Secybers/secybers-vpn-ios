//
//  KeychainHelper.swift
//  Secybers VPN
//
//  Stores sensitive data (passwords, tokens) securely in the iOS Keychain.
//  UserDefaults is unencrypted; the Keychain is encrypted by iOS.
//

import Foundation
import Security

final class KeychainHelper {
    
    static let shared = KeychainHelper()
    private let service = "com.secybers.secybers-vpn"
    
    private init() {}
    
    // MARK: - Save
    
    func save(_ value: String, forKey key: String) {
        guard let data = value.data(using: .utf8) else { return }
        
        // Remove any existing value first
        delete(forKey: key)
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]
        
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            print("Keychain save error for key '\(key)': \(status)")
        }
    }
    
    // MARK: - Read
    
    func read(forKey key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let value = String(data: data, encoding: .utf8) else {
            return nil
        }
        
        return value
    }
    
    // MARK: - Delete
    
    func delete(forKey key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key
        ]
        
        SecItemDelete(query as CFDictionary)
    }
    
    // MARK: - Delete All (used on logout)
    
    func deleteAll() {
        delete(forKey: "password")
        delete(forKey: "accessToken")
    }
}
