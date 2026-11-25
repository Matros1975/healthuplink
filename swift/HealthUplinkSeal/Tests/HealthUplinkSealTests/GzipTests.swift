import Foundation
import HealthUplinkSeal
import XCTest

final class GzipTests: XCTestCase {
    func testGzipHeaderAndLimit() throws {
        let gz = try Gzip.compress(Data(repeating: 0x30, count: 100_000))
        XCTAssertEqual(Array(gz.prefix(3)), [0x1f, 0x8b, 0x08])
        XCTAssertEqual(try Gzip.decompress(gz, limit: 100_000).count, 100_000)
        XCTAssertThrowsError(try Gzip.decompress(gz, limit: 99_999)) { XCTAssertEqual($0 as? GzipError, .tooLarge) }
    }
}
