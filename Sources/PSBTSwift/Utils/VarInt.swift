//
//  VarInt.swift
//
//
//  Created by 薛跃杰 on 2024/1/11.
//

import Foundation

public class VarInt {
    public let value: Int64
    public let originallyEncodedSize: Int

    public init(value: Int64) {
        self.value = value
        self.originallyEncodedSize = VarInt.sizeOf(value)
    }

    public init(buf: [UInt8], offset: Int) {
        let first = Int(buf[offset])
        if first < 253 {
            value = Int64(first)
            originallyEncodedSize = 1 // 1 data byte (8 bits)
        } else if first == 253 {
            value = Int64(buf[offset + 1]) | Int64(buf[offset + 2]) << 8
            originallyEncodedSize = 3 // 1 marker + 2 data bytes (16 bits)
        } else if first == 254 {
            value = Int64(Utils.readUint32(bytes: buf, offset: offset + 1))
            originallyEncodedSize = 5 // 1 marker + 4 data bytes (32 bits)
        } else {
            value = Int64(Utils.readInt64(bytes: buf, offset: offset + 1))
            originallyEncodedSize = 9 // 1 marker + 8 data bytes (64 bits)
        }
    }

    public func getSizeInBytes() -> Int {
        return VarInt.sizeOf(value)
    }

    public static func sizeOf(_ value: Int64) -> Int {
        if value < 0 { return 9 } // 1 marker + 8 data bytes
        if value < 253 { return 1 } // 1 data byte
        if value <= 0xFFFF { return 3 } // 1 marker + 2 data bytes
        if value <= 0xFFFFFFFF { return 5 } // 1 marker + 4 data bytes
        return 9 // 1 marker + 8 data bytes
    }

    public func encode() -> [UInt8] {
        var bytes: [UInt8]
        switch VarInt.sizeOf(value) {
        case 1:
            return [UInt8(value)]
        case 3:
            return [253, UInt8(value), UInt8(value >> 8)]
        case 5:
            bytes = [UInt8](repeating: 0, count: 5)
            bytes[0] = 254
            Utils.uint32ToByteArrayLE(val: Int64(value), out: &bytes, offset: 1)
            return bytes
        default:
            bytes = [UInt8](repeating: 0, count: 9)
            bytes[0] = 255
            Utils.uint64ToByteArrayLE(val: Int64(value), out: &bytes, offset: 1)
            return bytes
        }
    }
}
