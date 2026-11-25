import CryptoKit
import Foundation
import HealthUplinkSeal
import XCTest

final class VectorTests: XCTestCase {
    func testOpensReceiverVector() throws {
        let v = try Vectors.load()
        let sk = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: v.hex("server_sk"))
        XCTAssertEqual(sk.publicKey.rawRepresentation, v.hex("server_pk"))
        var r = try HPKE.Recipient(privateKey: sk, ciphersuite: .Curve25519_SHA256_ChachaPoly,
                                   info: v.hex("info"), encapsulatedKey: v.hex("enc"))
        let gz = try r.open(v.hex("ciphertext"), authenticating: v.hex("aad"))
        XCTAssertEqual(try Gzip.decompress(gz, limit: 16 << 20), Data(v.str("body_json").utf8))
    }

    func testVectorSignatureVerifies() throws {
        let v = try Vectors.load()
        let pk = try Curve25519.Signing.PublicKey(rawRepresentation: v.hex("device_pk"))
        XCTAssertTrue(pk.isValidSignature(v.hex("sig"), for: v.hex("sig_msg")))
        XCTAssertEqual(try Curve25519.Signing.PrivateKey(rawRepresentation: v.hex("device_sk")).publicKey.rawRepresentation,
                       v.hex("device_pk"))
    }

    private func sealVector(_ v: Vectors, seq: UInt64 = 7) throws -> (Envelope, ReceiverKey) {
        let receiver = ReceiverKey(deviceID: v.str("device_id"), serverPK: v.hex("server_pk"),
                                   keyEpoch: UInt32(v.int("key_epoch")))
        let signer = try Curve25519.Signing.PrivateKey(rawRepresentation: v.hex("device_sk"))
        let gz = try Gzip.compress(Data(v.str("body_json").utf8))
        let env = try Sealer.seal(gzipped: gz, batchID: v.str("batch_id"), seq: seq,
                                  createdAt: v.str("created_at"), receiver: receiver, signer: signer)
        return (env, receiver)
    }

    func testSealOpensAndVerifies() throws {
        let v = try Vectors.load()
        let (env, receiver) = try sealVector(v)
        XCTAssertEqual(env.envelopeVersion, 1)
        XCTAssertEqual(env.batchID, v.str("batch_id"))
        XCTAssertEqual(env.deviceID, v.str("device_id"))
        XCTAssertEqual(env.keyEpoch, 1)
        XCTAssertEqual(env.seq, 7)
        XCTAssertEqual(env.createdAt, v.str("created_at"))

        let aad = Messages.batchAAD(batchID: env.batchID, deviceID: env.deviceID, keyEpoch: env.keyEpoch,
                                    seq: env.seq, createdAt: env.createdAt)
        let enc = Data(base64Encoded: env.enc)!, ct = Data(base64Encoded: env.ciphertext)!
        let sk = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: v.hex("server_sk"))
        var r = try HPKE.Recipient(privateKey: sk, ciphersuite: .Curve25519_SHA256_ChachaPoly,
                                   info: Messages.batchInfo(deviceID: receiver.deviceID, serverPK: receiver.serverPK),
                                   encapsulatedKey: enc)
        let gz = try r.open(ct, authenticating: aad)
        XCTAssertEqual(try Gzip.decompress(gz, limit: 16 << 20), Data(v.str("body_json").utf8))
        let pk = try Curve25519.Signing.PublicKey(rawRepresentation: v.hex("device_pk"))
        XCTAssertTrue(pk.isValidSignature(Data(base64Encoded: env.sig)!,
                                          for: Messages.batchSigMsg(aad: aad, enc: enc, ciphertext: ct)))
    }


    func testEmitIOSVector() throws {
        guard let out = ProcessInfo.processInfo.environment["HU_VECTOR_OUT"] else {
            throw XCTSkip("HU_VECTOR_OUT not set")
        }
        let v = try Vectors.load()
        let (env, _) = try sealVector(v)
        let envData = try JSONEncoder().encode(env)
        let envObj = try JSONSerialization.jsonObject(with: envData)
        let doc: [String: Any] = ["server_pk": v.str("server_pk"), "device_pk": v.str("device_pk"),
                                  "body_json": v.str("body_json"), "envelope": envObj]
        let data = try JSONSerialization.data(withJSONObject: doc, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
        try data.write(to: URL(fileURLWithPath: out))
    }
}
