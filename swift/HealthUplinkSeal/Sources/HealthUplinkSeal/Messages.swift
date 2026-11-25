import CryptoKit
import Foundation

/// Signed and authenticated messages from the data contract.
public enum Messages {
    public static func batchAAD(batchID: String, deviceID: String, keyEpoch: UInt32, seq: UInt64, createdAt: String) -> Data {
        Wire.lp(batchID) + Wire.lp(deviceID) + Wire.u32(keyEpoch) + Wire.u64(seq) + Wire.lp(createdAt)
    }

    public static func batchInfo(deviceID: String, serverPK: Data) -> Data {
        Data("healthuplink/v1".utf8) + Wire.lp(deviceID) + serverPK
    }

    public static func batchSigMsg(aad: Data, enc: Data, ciphertext: Data) -> Data {
        Data("HUv1-batch".utf8) + aad + Wire.lp(enc) + Data(SHA256.hash(data: ciphertext))
    }

    public static func pairProofMsg(pairToken: Data, devicePK: Data) -> Data {
        Data("HUv1-pair".utf8) + Wire.lp(pairToken) + Wire.lp(devicePK)
    }

    public static func pairConfirm(pairToken: Data, devicePK: Data, serverPK: Data) -> Data {
        let mac = HMAC<SHA256>.authenticationCode(for: devicePK + serverPK, using: SymmetricKey(data: pairToken))
        return Data(mac)
    }

    public static func unpairMsg(deviceID: String, at: String) -> Data {
        Data("HUv1-unpair".utf8) + Wire.lp(deviceID) + Wire.lp(at)
    }

    public static func statusMsg(deviceID: String, at: String) -> Data {
        Data("HUv1-status".utf8) + Wire.lp(deviceID) + Wire.lp(at)
    }
}
