import CryptoKit
import Foundation

public struct ReceiverKey: Codable, Equatable, Sendable {
    public let deviceID: String
    public let serverPK: Data
    public let keyEpoch: UInt32

    public init(deviceID: String, serverPK: Data, keyEpoch: UInt32) {
        self.deviceID = deviceID
        self.serverPK = serverPK
        self.keyEpoch = keyEpoch
    }
}

public struct Envelope: Codable, Equatable, Sendable {
    public var envelopeVersion: Int = 1
    public let batchID: String
    public let deviceID: String
    public let keyEpoch: UInt32
    public let seq: UInt64
    public let createdAt: String
    public let enc: String
    public let ciphertext: String
    public let sig: String

    public init(envelopeVersion: Int = 1, batchID: String, deviceID: String, keyEpoch: UInt32, seq: UInt64,
                createdAt: String, enc: String, ciphertext: String, sig: String) {
        self.envelopeVersion = envelopeVersion
        self.batchID = batchID
        self.deviceID = deviceID
        self.keyEpoch = keyEpoch
        self.seq = seq
        self.createdAt = createdAt
        self.enc = enc
        self.ciphertext = ciphertext
        self.sig = sig
    }

    enum CodingKeys: String, CodingKey {
        case envelopeVersion = "envelope_version"
        case batchID = "batch_id"
        case deviceID = "device_id"
        case keyEpoch = "key_epoch"
        case seq
        case createdAt = "created_at"
        case enc, ciphertext, sig
    }
}

public enum Sealer {
    /// HPKE-seals gzipped body once, then signs the batch message.
    public static func seal(gzipped: Data, batchID: String, seq: UInt64, createdAt: String,
                            receiver: ReceiverKey, signer: Curve25519.Signing.PrivateKey) throws -> Envelope {
        let info = Messages.batchInfo(deviceID: receiver.deviceID, serverPK: receiver.serverPK)
        let aad = Messages.batchAAD(batchID: batchID, deviceID: receiver.deviceID,
                                    keyEpoch: receiver.keyEpoch, seq: seq, createdAt: createdAt)
        let recipient = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: receiver.serverPK)
        var sender = try HPKE.Sender(recipientKey: recipient, ciphersuite: .Curve25519_SHA256_ChachaPoly, info: info)
        let ciphertext = try sender.seal(gzipped, authenticating: aad)
        let enc = sender.encapsulatedKey
        let sig = try signer.signature(for: Messages.batchSigMsg(aad: aad, enc: enc, ciphertext: ciphertext))
        return Envelope(batchID: batchID, deviceID: receiver.deviceID, keyEpoch: receiver.keyEpoch, seq: seq,
                        createdAt: createdAt, enc: enc.base64EncodedString(),
                        ciphertext: ciphertext.base64EncodedString(), sig: sig.base64EncodedString())
    }
}
