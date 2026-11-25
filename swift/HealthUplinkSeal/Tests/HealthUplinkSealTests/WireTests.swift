import XCTest
import HealthUplinkSeal

final class WireTests: XCTestCase {
    func testMessagesMatchGoldenVectors() throws {
        let v = try Vectors.load()
        let aad = Messages.batchAAD(batchID: v.str("batch_id"), deviceID: v.str("device_id"),
                                    keyEpoch: 1, seq: 7, createdAt: v.str("created_at"))
        XCTAssertEqual(aad, v.hex("aad"))
        XCTAssertEqual(Messages.batchInfo(deviceID: v.str("device_id"), serverPK: v.hex("server_pk")), v.hex("info"))
        XCTAssertEqual(Messages.batchSigMsg(aad: aad, enc: v.hex("enc"), ciphertext: v.hex("ciphertext")), v.hex("sig_msg"))
        XCTAssertEqual(Messages.pairProofMsg(pairToken: v.hex("pair_token"), devicePK: v.hex("device_pk")), v.hex("pair_proof_msg"))
        XCTAssertEqual(Messages.pairConfirm(pairToken: v.hex("pair_token"), devicePK: v.hex("device_pk"),
                                            serverPK: v.hex("server_pk")), v.hex("pair_confirm"))
        XCTAssertEqual(Messages.unpairMsg(deviceID: v.str("device_id"), at: v.str("at")), v.hex("unpair_msg"))
        XCTAssertEqual(Messages.statusMsg(deviceID: v.str("device_id"), at: v.str("at")), v.hex("status_msg"))
    }

    func testTimestampIsWholeSecondUTC() {
        XCTAssertEqual(Wire.timestamp(Date(timeIntervalSince1970: 1_795_332_612.999)), "2026-11-22T07:30:12Z")
    }

    private static func reference() -> ISO8601DateFormatter {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        f.timeZone = TimeZone(identifier: "UTC")!
        return f
    }

    /// The cached formatting gives the same bytes as a fresh `ISO8601DateFormatter`, and parsing inverts it.
    func testTimestampMatchesTheFormatterForManyDates() {
        let ref = Self.reference()
        var rng = SystemRandomNumberGenerator()
        var dates: [Date] = [0, 1, 59.999, 86_399.5, 951_782_400, 951_868_799, 1_709_164_800, 1_735_689_599.9,
                             1_795_332_612.999, 4_102_444_799, 4_107_542_400, 253_402_300_799].map(Date.init(timeIntervalSince1970:))
        for _ in 0..<5000 { dates.append(Date(timeIntervalSince1970: Double.random(in: 0..<4_200_000_000, using: &rng))) }
        for d in dates {
            let floored = Date(timeIntervalSince1970: d.timeIntervalSince1970.rounded(.down))
            let s = Wire.timestamp(d)
            XCTAssertEqual(s, ref.string(from: floored), "\(d.timeIntervalSince1970)")
            XCTAssertEqual(Wire.parseTimestamp(s), floored, s)
        }
    }

    /// Parsing accepts exactly what the formatter accepts, with the same result.
    func testParseTimestampMatchesTheFormatter() {
        let ref = Self.reference()
        for s in ["2026-11-22T07:30:12Z", "2026-11-22T08:30:12+01:00", "2026-11-22T07:30:12z", "2026-02-30T00:00:00Z",
                  "2026-13-01T00:00:00Z", "2026-11-22T24:00:00Z", "2026-11-22T23:59:60Z", "2026-11-22 07:30:12Z",
                  "2026-11-22T07:30:12", "2026-11-22T07:30:12.5Z", "0999-01-01T00:00:00Z", "1969-12-31T23:59:59Z",
                  "2024-02-29T12:00:00Z", "2023-02-29T12:00:00Z", "２026-11-22T07:30:12Z", "", "garbage"] {
            XCTAssertEqual(Wire.parseTimestamp(s), ref.date(from: s), s)
        }
    }

    /// The first history upload formats and parses two timestamps per sample: a fresh formatter per call made
    /// that about half a millisecond per sample.
    func testTimestampAndParseAreFast() {
        let base = Date(timeIntervalSince1970: 1_795_332_612)
        let start = Date()
        for i in 0..<20_000 {
            let s = Wire.timestamp(base + Double(i) * 61)
            XCTAssertNotNil(Wire.parseTimestamp(s))
        }
        XCTAssertLessThan(Date().timeIntervalSince(start), 1.5)
    }

    func testDayKeyUsesGivenZone() {
        let d = Date(timeIntervalSince1970: 1_795_302_000) // 2026-11-21T23:00:00Z
        XCTAssertEqual(Wire.dayKey(d, in: TimeZone(identifier: "Europe/Amsterdam")!), "2026-11-22")
        XCTAssertEqual(Wire.dayKey(d, in: TimeZone(identifier: "UTC")!), "2026-11-21")
    }

    func testUUIDv7Layout() {
        let id = Wire.uuidV7(now: Date(timeIntervalSince1970: 1_795_332_612))
        XCTAssertEqual(id, id.lowercased())
        XCTAssertEqual(Array(id)[14], "7")
        XCTAssertTrue("89ab".contains(Array(id)[19]))
        XCTAssertEqual(String(id.prefix(13)).replacingOccurrences(of: "-", with: ""), String(format: "%012llx", 1_795_332_612_000))
    }
}
