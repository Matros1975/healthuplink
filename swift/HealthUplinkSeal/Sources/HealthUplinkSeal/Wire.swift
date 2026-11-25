import Foundation

/// Byte-exact encoders from the data contract; mirror `receiver/src/healthuplink/encoding.py`.
public enum Wire {
    /// 4-byte big-endian length followed by the bytes.
    public static func lp(_ data: Data) -> Data { u32(UInt32(data.count)) + data }

    public static func lp(_ string: String) -> Data { lp(Data(string.utf8)) }

    public static func u32(_ n: UInt32) -> Data {
        Data((0..<4).map { UInt8(truncatingIfNeeded: n >> UInt32(24 - 8 * $0)) })
    }

    public static func u64(_ n: UInt64) -> Data {
        Data((0..<8).map { UInt8(truncatingIfNeeded: n >> UInt64(56 - 8 * $0)) })
    }

    /// UTC `yyyy-MM-dd'T'HH:mm:ss'Z'`, whole seconds (floored). Plain integer arithmetic (a fresh
    /// `ISO8601DateFormatter` per call cost about a third of a millisecond, and the history upload formats two
    /// timestamps per sample); years outside 1970...9999 go through the shared formatter. Same bytes either way.
    public static func timestamp(_ date: Date) -> String {
        let seconds = date.timeIntervalSince1970.rounded(.down)
        guard seconds >= 0, seconds < 253_402_300_800, let total = Int(exactly: seconds) else {
            return ISOFormatter.shared.string(from: Date(timeIntervalSince1970: seconds))
        }
        let days = total / 86_400, rest = total % 86_400
        let (y, m, d) = civil(days: days)
        var out = [UInt8]()
        out.reserveCapacity(20)
        func put(_ n: Int, _ width: Int) {
            var digits = [UInt8](repeating: 0x30, count: width)
            var v = n
            for i in stride(from: width - 1, through: 0, by: -1) { digits[i] = 0x30 + UInt8(v % 10); v /= 10 }
            out += digits
        }
        put(y, 4); out.append(0x2D); put(m, 2); out.append(0x2D); put(d, 2); out.append(0x54)
        put(rest / 3600, 2); out.append(0x3A); put(rest / 60 % 60, 2); out.append(0x3A); put(rest % 60, 2); out.append(0x5A)
        return String(decoding: out, as: UTF8.self)
    }

    /// The inverse of `timestamp`; nil for anything that is not an internet date-time. The exact shape
    /// `timestamp` writes is parsed directly; anything else (offsets, other years, invalid fields) goes through
    /// the shared formatter, so the result is the formatter's.
    public static func parseTimestamp(_ s: String) -> Date? {
        let b = Array(s.utf8)
        if b.count == 20, b[4] == 0x2D, b[7] == 0x2D, b[10] == 0x54, b[13] == 0x3A, b[16] == 0x3A, b[19] == 0x5A {
            func num(_ r: Range<Int>) -> Int? {
                var v = 0
                for i in r {
                    guard (0x30...0x39).contains(b[i]) else { return nil }
                    v = v * 10 + Int(b[i] - 0x30)
                }
                return v
            }
            if let y = num(0..<4), let m = num(5..<7), let d = num(8..<10), let h = num(11..<13), let mi = num(14..<16),
               let sec = num(17..<19), y >= 1970, (1...12).contains(m), d >= 1, d <= daysIn(month: m, year: y),
               h < 24, mi < 60, sec < 60 {
                let days = daysFromCivil(y, m, d)
                return Date(timeIntervalSince1970: TimeInterval(days * 86_400 + h * 3600 + mi * 60 + sec))
            }
        }
        return ISOFormatter.shared.date(from: s)
    }

    /// Proleptic Gregorian date of a day count since 1970-01-01 (H. Hinnant's `civil_from_days`), days >= 0.
    private static func civil(days: Int) -> (Int, Int, Int) {
        let z = days + 719_468
        let era = z / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        return (yoe + era * 400 + (m <= 2 ? 1 : 0), m, d)
    }

    /// Days since 1970-01-01 of a proleptic Gregorian date, years >= 1970.
    private static func daysFromCivil(_ year: Int, _ m: Int, _ d: Int) -> Int {
        let y = m <= 2 ? year - 1 : year
        let era = y / 400
        let yoe = y - era * 400
        let doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    private static func daysIn(month m: Int, year y: Int) -> Int {
        switch m {
        case 2: return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 ? 29 : 28
        case 4, 6, 9, 11: return 30
        default: return 31
        }
    }

    /// The one calendar helper: Gregorian in the given zone.
    public static func calendar(in zone: TimeZone) -> Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = zone
        return calendar
    }

    public static func dayKey(_ date: Date, in zone: TimeZone) -> String {
        dayKey(date, calendar: calendar(in: zone))
    }

    /// `dayKey` with a calendar the caller already built (from `calendar(in:)`), for loops over many dates.
    public static func dayKey(_ date: Date, calendar: Calendar) -> String {
        let c = calendar.dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", c.year!, c.month!, c.day!)
    }

    /// Lowercase UUIDv7: 48-bit Unix ms, version 7, variant 10, 74 random bits.
    public static func uuidV7(now: Date) -> String {
        let ms = UInt64((now.timeIntervalSince1970 * 1000).rounded(.down))
        var rng = SystemRandomNumberGenerator()
        var b = [UInt8](repeating: 0, count: 16)
        for i in 0..<6 { b[i] = UInt8(truncatingIfNeeded: ms >> UInt64(40 - 8 * i)) }
        for i in 6..<16 { b[i] = UInt8.random(in: 0...255, using: &rng) }
        b[6] = (b[6] & 0x0F) | 0x70
        b[8] = (b[8] & 0x3F) | 0x80
        let hex = b.map { String(format: "%02x", $0) }.joined()
        let h = Array(hex)
        func part(_ r: Range<Int>) -> String { String(h[r]) }
        return [part(0..<8), part(8..<12), part(12..<16), part(16..<20), part(20..<32)].joined(separator: "-")
    }
}

/// One shared internet date-time formatter (UTC) for the rare inputs `Wire` does not handle itself. Formatting
/// and parsing take a lock, so the formatter is never used by two threads at once.
public final class ISOFormatter: @unchecked Sendable {
    public static let shared = ISOFormatter()
    private let lock = NSLock()
    private let formatter: ISO8601DateFormatter

    private init() {
        formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(identifier: "UTC")!
    }

    public func string(from date: Date) -> String { lock.withLock { formatter.string(from: date) } }
    public func date(from string: String) -> Date? { lock.withLock { formatter.date(from: string) } }
}
