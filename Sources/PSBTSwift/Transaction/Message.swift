//
//  Message.swift
//
//
//  Created by 薛跃杰 on 2024/1/11.
//

import Foundation
import BigInt
import CryptoSwift

public class Message {
    public static let MAX_SIZE = 0x02000000 // 32MB
    public static let UNKNOWN_LENGTH = Int.min
    
    public var payload: [UInt8]?
    
    // The offset is how many bytes into the provided byte array this message payload starts at.
    public var offset: Int
    // The cursor keeps track of where we are in the byte array as we parse it.
    // Note that it's relative to the start of the array NOT the start of the message payload.
    public var cursor: Int
    
    public var length = UNKNOWN_LENGTH
    
    public init() {
        self.offset = 0
        self.cursor = 0
    }
    
    public init(payload: [UInt8], offset: Int) {
        self.payload = payload
        self.offset = offset
        self.cursor = self.offset
        
        do {
            try parse()
        } catch {
            // handle error
        }
    }
    
    public func parse() throws {
       
    }
    
    /**
     * This returns a correct value by parsing the message.
     */
    public final func getMessageSize() throws -> Int {
        if length == Message.UNKNOWN_LENGTH {
            throw PSBTError.unknow
        }
        
        return length
    }
    
    public func readUint32() -> UInt32 {
        let u = Utils.readUint32(bytes: payload!, offset: cursor)
        cursor += 4
        return u
    }
    
    public func readInt64() -> Int64 {
        let u = Utils.readInt64(bytes: payload!, offset: cursor)
        cursor += 8
        return Int64(u)
    }
    
    public func readBytes(length: Int) throws -> [UInt8] {
        if length > Message.MAX_SIZE || cursor + length > payload!.count {
            throw PSBTError.message("Claimed value length too large: \(length)")
        }
        var b = [UInt8](repeating: 0, count: length)
        b = Array(payload![cursor..<(cursor + length)])
        cursor += length
        return b
    }
    
    public func readVarInt() -> Int64 {
        return readVarInt(offset: 0)
    }
    
    public func readVarInt(offset: Int) -> Int64 {
        let varint = VarInt(buf: payload!, offset: cursor + offset)
        cursor += offset + varint.originallyEncodedSize
        return varint.value
    }
    
    public func readHash() throws -> Data {
        return Data(Data(try readBytes(length: 32)).reversed())
    }
    
    public func bitcoinSerializeToData(data: inout Data) throws {
        throw PSBTError.message("Error: {} class has not implemented bitcoinSerializeToStream method.  Generating message with no payload")
    }
    
    public func adjustLength(adjustment: Int) {
        adjustLength(newArraySize: 0, adjustment: adjustment)
    }
    
    public func adjustLength(newArraySize: Int, adjustment: Int) {
        if length == Message.UNKNOWN_LENGTH {
            return
        }
        if adjustment == Message.UNKNOWN_LENGTH {
            length = Message.UNKNOWN_LENGTH
            return
        }
        length += adjustment
        if newArraySize == 1 {
            length += 1
        } else if newArraySize != 0 {
            length += VarInt.sizeOf(Int64(newArraySize)) - VarInt.sizeOf(Int64(newArraySize - 1))
        }
    }
}
