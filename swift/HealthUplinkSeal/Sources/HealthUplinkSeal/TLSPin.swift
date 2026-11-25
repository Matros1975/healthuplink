import CryptoKit
import Foundation
import Security

/// TLS certificate pins for self-signed receivers: base64 SHA-256 of the leaf certificate's
/// SubjectPublicKeyInfo, P-256 keys only.
public enum TLSPin {
    /// DER prefix of a P-256 SubjectPublicKeyInfo (id-ecPublicKey, prime256v1, 66-byte bit string); the
    /// 65-byte uncompressed point follows it.
    public static let p256SPKIHeader = Data([
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ])

    /// Pin of a P-256 public key given as an uncompressed point (`04 || x || y`); nil for anything else.
    public static func spkiSHA256(p256Uncompressed key: Data) -> String? {
        guard key.count == 65, key.first == 0x04 else { return nil }
        return Data(SHA256.hash(data: p256SPKIHeader + key)).base64EncodedString()
    }

    /// Pin of the leaf certificate's key; nil unless that key is EC with a 256-bit size.
    public static func spkiSHA256(leafOf trust: SecTrust) -> String? {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first,
              let key = SecCertificateCopyKey(leaf),
              let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
              let type = attributes[kSecAttrKeyType] as? String, type == (kSecAttrKeyTypeECSECPrimeRandom as String),
              let bits = attributes[kSecAttrKeySizeInBits] as? Int, bits == 256,
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data?
        else { return nil }
        return spkiSHA256(p256Uncompressed: raw)
    }

    /// True when the leaf's pin equals `pin`, compared in constant time. Host name and chain validity are not
    /// checked: the pin alone decides.
    public static func matches(_ trust: SecTrust, pin: String) -> Bool {
        guard let actual = spkiSHA256(leafOf: trust) else { return false }
        let a = Array(actual.utf8), b = Array(pin.utf8)
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in a.indices { diff |= a[i] ^ b[i] }
        return diff == 0
    }
}
