import Foundation
import zlib

public enum GzipError: Error, Equatable {
    case tooLarge
    case zlib(Int32)
}

/// Single-member gzip through the system zlib (windowBits 31 = gzip wrapper).
public enum Gzip {
    public static func compress(_ input: Data) throws -> Data {
        var stream = z_stream()
        let initStatus = deflateInit2_(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY,
                                       ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        guard initStatus == Z_OK else { throw GzipError.zlib(initStatus) }
        defer { deflateEnd(&stream) }

        var out = Data()
        let chunk = 64 * 1024
        var buffer = [UInt8](repeating: 0, count: chunk)
        var failure: Int32?
        input.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            stream.next_in = UnsafeMutablePointer(mutating: raw.bindMemory(to: UInt8.self).baseAddress)
            stream.avail_in = UInt32(raw.count)
            var status: Int32 = Z_OK
            repeat {
                buffer.withUnsafeMutableBufferPointer { buf in
                    stream.next_out = buf.baseAddress
                    stream.avail_out = UInt32(chunk)
                    status = deflate(&stream, Z_FINISH)
                    out.append(buf.baseAddress!, count: chunk - Int(stream.avail_out))
                }
            } while status == Z_OK
            if status != Z_STREAM_END { failure = status }
        }
        if let failure { throw GzipError.zlib(failure) }
        return out
    }

    public static func decompress(_ input: Data, limit: Int) throws -> Data {
        var stream = z_stream()
        let initStatus = inflateInit2_(&stream, 31, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        guard initStatus == Z_OK else { throw GzipError.zlib(initStatus) }
        defer { inflateEnd(&stream) }

        var out = Data()
        let chunk = 64 * 1024
        var buffer = [UInt8](repeating: 0, count: chunk)
        var failure: Error?
        input.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            stream.next_in = UnsafeMutablePointer(mutating: raw.bindMemory(to: UInt8.self).baseAddress)
            stream.avail_in = UInt32(raw.count)
            var status: Int32 = Z_OK
            repeat {
                buffer.withUnsafeMutableBufferPointer { buf in
                    stream.next_out = buf.baseAddress
                    stream.avail_out = UInt32(chunk)
                    status = inflate(&stream, Z_NO_FLUSH)
                    out.append(buf.baseAddress!, count: chunk - Int(stream.avail_out))
                }
                if out.count > limit { failure = GzipError.tooLarge; return }
                if status == Z_BUF_ERROR && stream.avail_in == 0 { status = Z_DATA_ERROR }
            } while status == Z_OK
            if status != Z_STREAM_END { failure = GzipError.zlib(status) }
        }
        if let failure { throw failure }
        return out
    }
}
