// SPDX-License-Identifier: MIT
import Foundation
import CryptoKit

public class PrivateKey: BaseKey {
    public var publicKey: PublicKey {
        let privKey = try! Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawValue)
        return PublicKey(rawValue: privKey.publicKey.rawRepresentation)!
    }

    convenience public init() {
        let privKey = Curve25519.KeyAgreement.PrivateKey()
        self.init(rawValue: privKey.rawRepresentation)!
    }
}

public class PublicKey: BaseKey {}
public class PreSharedKey: BaseKey {}

public class BaseKey: RawRepresentable, Equatable, Hashable {
    public let rawValue: Data

    public var base64Key: String {
        return rawValue.base64EncodedString()
    }

    public var hexKey: String {
        return rawValue.map { String(format: "%02x", $0) }.joined()
    }

    required public init?(rawValue: Data) {
        guard rawValue.count == 32 else { return nil }
        self.rawValue = rawValue
    }

    public convenience init?(base64Key: String) {
        guard let data = Data(base64Encoded: base64Key), data.count == 32 else { return nil }
        self.init(rawValue: data)
    }

    public convenience init?(hexKey: String) {
        guard hexKey.count == 64 else { return nil }
        var data = Data(capacity: 32)
        var index = hexKey.startIndex
        while index < hexKey.endIndex {
            let nextIndex = hexKey.index(index, offsetBy: 2)
            guard let byte = UInt8(hexKey[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self.init(rawValue: data)
    }

    public static func == (lhs: BaseKey, rhs: BaseKey) -> Bool {
        return lhs.rawValue == rhs.rawValue
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(rawValue)
    }
}
