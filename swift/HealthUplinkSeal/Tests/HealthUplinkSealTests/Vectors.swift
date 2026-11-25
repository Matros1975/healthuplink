import Foundation

/// Golden vectors from `contract/vectors/` (`v1.json` by default, `tls-v1.json` for the pin). `contract/` sits four
/// directories above this file's folder,
/// both in the app repository (`ios/HealthUplinkSeal/Tests/HealthUplinkSealTests`) and in the public layout.
struct Vectors {
    private let values: [String: Any]

    static let contractDirectory: URL = {
        var url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<4 { url.deleteLastPathComponent() }
        return url.appendingPathComponent("contract", isDirectory: true)
    }()

    static func load(_ file: String = "v1.json") throws -> Vectors {
        let url = contractDirectory.appendingPathComponent("vectors").appendingPathComponent(file)
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        guard let dict = object as? [String: Any] else { throw CocoaError(.fileReadCorruptFile) }
        return Vectors(values: dict)
    }

    func str(_ key: String) -> String { values[key] as! String }

    func int(_ key: String) -> Int { values[key] as! Int }

    /// A standard base64 field (tls-v1.json); fails the test run on a malformed value.
    func base64(_ key: String) -> Data { Data(base64Encoded: str(key))! }

    func hex(_ key: String) -> Data {
        let chars = Array(str(key))
        precondition(chars.count % 2 == 0, "odd hex length for \(key)")
        var out = Data()
        for i in stride(from: 0, to: chars.count, by: 2) {
            out.append(UInt8(String(chars[i...i + 1]), radix: 16)!)
        }
        return out
    }
}
