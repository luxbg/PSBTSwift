//
//  Utils.swift
//
//
//  Created by 薛跃杰 on 2024/1/11.
//

import Foundation
import BigInt
import CryptoSwift
import RIPEMDSwift

public struct Utils {
    
    public static let MAX_INITIAL_ARRAY_LENGTH: Int = 20
    private let hexArray = Array("0123456789abcdef")

    public static let HEX_REGEX = "^[0-9A-Fa-f]+$"
    public static let BASE64_REGEX = "^[0-9A-Za-z\\\\+=/]+$"
    public static let NUMERIC_REGEX = "^-?\\d+(\\.\\d+)?$"

    public static func isHex(s: String) -> Bool {
        return s.range(of: Utils.HEX_REGEX, options: .regularExpression) != nil
    }

    public static func isBase64(s: String) -> Bool {
        return s.range(of: Utils.BASE64_REGEX, options: .regularExpression) != nil
    }

    public static func isNumber(s: String) -> Bool {
        return s.range(of: Utils.NUMERIC_REGEX, options: .regularExpression) != nil
    }
    
    public static func isUtf8(bytes: [UInt8]) -> Bool {
        let string = String(data: Data(bytes), encoding: .utf8)
        return string != nil
    }
    
    public static func reverse(_ array: inout [UInt8]) {
        let count = array.count
        for i in 0..<count / 2 {
            array.swapAt(i, count - i - 1)
        }
    }
    
    public static func readUint16(_ bytes: [UInt8], offset: Int) -> Int {
        return (Int(bytes[offset]) & 0xff) |
                ((Int(bytes[offset + 1]) & 0xff) << 8)
    }
    
    public static func readUint16FromStream(_ data: Data) throws -> Int {
        guard data.count >= 2 else {
            throw NSError(domain: "DataError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Data is not long enough"])
        }
        let value = (Int(data[0]) & 0xff) |
                    ((Int(data[1]) & 0xff) << 8)
        return value
    }
    
    public static func readUint32FromStream(_ data: Data) throws -> Int {
        guard data.count >= 4 else {
            throw NSError(domain: "DataError", code: 0, userInfo: [NSLocalizedDescriptionKey: "Data is not long enough"])
        }
        let value = (Int(data[0]) & 0xff) |
                    ((Int(data[1]) & 0xff) << 8) |
                    ((Int(data[2]) & 0xff) << 16) |
                    ((Int(data[3]) & 0xff) << 24)
        return value
    }

    public static func readUint32(bytes: [UInt8], offset: Int) -> UInt32 {
        let value = (UInt32(bytes[offset]) & 0xFF) |
                    ((UInt32(bytes[offset + 1]) & 0xFF) << 8) |
                    ((UInt32(bytes[offset + 2]) & 0xFF) << 16) |
                    ((UInt32(bytes[offset + 3]) & 0xFF) << 24)
        return value
    }
    
    public static func readInt64(bytes: [UInt8], offset: Int) -> UInt64 {
        let value = (UInt64(bytes[offset]) & 0xFF) |
                    ((UInt64(bytes[offset + 1]) & 0xFF) << 8) |
                    ((UInt64(bytes[offset + 2]) & 0xFF) << 16) |
                    ((UInt64(bytes[offset + 3]) & 0xFF) << 24) |
                    ((UInt64(bytes[offset + 4]) & 0xFF) << 32) |
                    ((UInt64(bytes[offset + 5]) & 0xFF) << 40) |
                    ((UInt64(bytes[offset + 6]) & 0xFF) << 48) |
                    ((UInt64(bytes[offset + 7]) & 0xFF) << 56)
        return value
    }

    public static func reverseBytes(bytes: [UInt8]) -> [UInt8] {
        var buf = [UInt8](repeating: 0, count: bytes.count)
        for i in 0..<bytes.count {
            buf[i] = bytes[bytes.count - 1 - i]
        }
        return buf
    }
    
    public static func uint32ToByteArrayLE(val: Int64, out: inout [UInt8], offset: Int) {
        out[offset] = UInt8(val & 0xFF)
        out[offset + 1] = UInt8((val >> 8) & 0xFF)
        out[offset + 2] = UInt8((val >> 16) & 0xFF)
        out[offset + 3] = UInt8((val >> 24) & 0xFF)
    }
    
    public static func uint64ToByteArrayLE(val: Int64, out: inout [UInt8], offset: Int) {
        out[offset] = UInt8(0xFF & val)
        out[offset + 1] = UInt8(0xFF & (val >> 8))
        out[offset + 2] = UInt8(0xFF & (val >> 16))
        out[offset + 3] = UInt8(0xFF & (val >> 24))
        out[offset + 4] = UInt8(0xFF & (val >> 32))
        out[offset + 5] = UInt8(0xFF & (val >> 40))
        out[offset + 6] = UInt8(0xFF & (val >> 48))
        out[offset + 7] = UInt8(0xFF & (val >> 56))
    }
    
    public static func int64ToDataLE(val: Int64, data: inout Data) {
        data.append(UInt8(0xFF & val))
        data.append(UInt8(0xFF & (val >> 8)))
        data.append(UInt8(0xFF & (val >> 16)))
        data.append(UInt8(0xFF & (val >> 24)))
        data.append(UInt8(0xFF & (val >> 32)))
        data.append(UInt8(0xFF & (val >> 40)))
        data.append(UInt8(0xFF & (val >> 48)))
        data.append(UInt8(0xFF & (val >> 56)))
    }
    
    public static func uint64ToDataLE(val: BigInt, data: inout Data) throws {
        var bytes = val.serialize()
        if bytes.count > 8 {
            throw NSError(domain: "", code: 0, userInfo: [NSLocalizedDescriptionKey: "Input too large to encode into a uint64"])
        }
        bytes = Data(bytes.reversed())
        data.append(contentsOf: bytes)
        if bytes.count < 8 {
            for _ in 0..<8 - bytes.count {
                data.append(0)
            }
        }
    }
    
    
    public static func uint32ToDataLE(val: Int, outData: inout Data) throws {
        var bytes = [UInt8](repeating: 0, count: 4)
        bytes[0] = UInt8(val & 0xFF)
        bytes[1] = UInt8((val >> 8) & 0xFF)
        bytes[2] = UInt8((val >> 16) & 0xFF)
        bytes[3] = UInt8((val >> 24) & 0xFF)
        outData.append(contentsOf: bytes)
    }
    
    
    public static func uint16ToDataLE(val: UInt16, outData: inout Data) throws {
        var bytes = [UInt8](repeating: 0, count: 4)
        bytes[0] = UInt8(val & 0xFF)
        bytes[1] = UInt8((val >> 8) & 0xFF)
        bytes[2] = UInt8((val >> 16) & 0xFF)
        bytes[3] = UInt8((val >> 24) & 0xFF)
        outData.append(contentsOf: bytes)
    }
    
    public static func currentTimeSeconds() -> Int {
        return Int(Date().timeIntervalSince1970)
    }
    
    public static func dateTimeFormat(dateTime: TimeInterval) -> String {
        let date = Date(timeIntervalSince1970: dateTime)
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withFullDate, .withTime, .withDashSeparatorInDate, .withColonSeparatorInTime]
        return formatter.string(from: date)
    }
    
    public static func join<T>(_ items: [T]) -> String {
        return items.map { "\($0)" }.joined(separator: " ")
    }
    
    public static func taggedHash(tag: String, msg: [UInt8]) -> [UInt8] {
        let hash = tag.data(using: .utf8)!.sha256()
        var buffer = Data()
        buffer.append(hash)
        buffer.append(hash)
        buffer.append(Data(msg))

        return buffer.sha256().bytes
    }
    
    public static func sha256hash160(input: [UInt8]) -> Data? {
        return Data(input).hash160()
    }
    
    public static func bech32ConvertBits(from: Int, to: Int, pad: Bool, idata: [UInt8]) -> Data? {
        var acc: Int = 0
        var bits: Int = 0
        let maxv: Int = (1 << to) - 1
        let maxAcc: Int = (1 << (from + to - 1)) - 1
        var odata = Data()
        let idataData = Data(idata)
        for ibyte in idataData {
            acc = ((acc << from) | Int(ibyte)) & maxAcc
            bits += from
            while bits >= to {
                bits -= to
                odata.append(UInt8((acc >> bits) & maxv))
            }
        }
        if pad {
            if bits != 0 {
                odata.append(UInt8((acc << (to - bits)) & maxv))
            }
        } else if (bits >= from || ((acc << (to - bits)) & maxv) != 0) {
            return nil
        }
        return odata
    }
    
    public static func getDataXCoord(_ data: Data) -> Data? {
        guard let payload = try? SchnorrHelper.tweakedOutputKey(publicKey: data) else{
            return nil
        }
        return payload
    }
    
    public static func appendChild(path: [ChildNumber], childNumber: ChildNumber) -> [ChildNumber] {
        var childPath = [ChildNumber]()
        childPath.append(contentsOf: path)
        childPath.append(childNumber)
        return childPath
    }
    
    public static func getHmacSha512Hash(key: [UInt8], data: [UInt8]) -> [UInt8]? {
        let hmac:Authenticator = HMAC(key: key, variant: .sha2(.sha512))
        guard let entropy = try? hmac.authenticate(data) else {return nil}
        return entropy
    }
}

extension Array where Element == UInt8 {
    public func encodeChecked(version: Int) -> String {
        if version < 0 || version > 255 {
            return ""
        }
        var addressBytes = Data(capacity: 1 + self.count + 4)
        addressBytes.append(contentsOf: [UInt8(version)])
        addressBytes.append(contentsOf: self)
        return addressBytes.bytes.base58CheckEncodedString
    }
}

extension Data {
    public func hash160() -> Data? {
        return try? RIPEMD160.hash(message: self.sha256())
    }
    
    public func hash256() -> Data {
        return self.sha256().sha256()
    }
}
