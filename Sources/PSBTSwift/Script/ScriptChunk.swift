//
//  ScriptChunk.swift
//
//
//  Created by 薛跃杰 on 2024/1/16.
//

import Foundation

public class ScriptChunk {
    public var opcode: Int
    public let data: [UInt8]?

    public init(opcode: Int, data: [UInt8]?) {
        self.opcode = opcode
        self.data = data
    }
    
    public static func fromOpcode(opcode: Int) -> ScriptChunk {
        return ScriptChunk(opcode: opcode, data: opcode == ScriptOpCodes.OP_0 ? [] : nil)
    }
    
    public static func fromData(data: [UInt8]) throws -> ScriptChunk {
        let copy = data
        var opcode: Int
        if data.count == 0 {
            opcode = ScriptOpCodes.OP_0
        } else if data.count == 1 {
            let b = data[0]
            if b >= 1 && b <= 16 {
                opcode = try Script.encodeToOpN(Int(b))
            } else {
                opcode = 1
            }
        } else if data.count < ScriptOpCodes.OP_PUSHDATA1 {
            opcode = data.count
        } else if data.count < 256 {
            opcode = ScriptOpCodes.OP_PUSHDATA1
        } else if data.count < 65536 {
            opcode = ScriptOpCodes.OP_PUSHDATA2
        } else {
            opcode = ScriptOpCodes.OP_PUSHDATA4
        }

        return ScriptChunk(opcode: opcode, data: copy)
    }

    public func equalsOpCode(_ opcode: Int) -> Bool {
        return opcode == self.opcode
    }

    public func isOpCode() -> Bool {
        return opcode > ScriptOpCodes.OP_PUSHDATA4
    }

    public func isPushData() -> Bool {
        return opcode <= ScriptOpCodes.OP_16
    }

    public func decodeOpN() throws -> Int {
        assert(isOpCode())
        return try Script.decodeFromOpN(opcode)
    }

    public func isShortestPossiblePushData() -> Bool {
        assert(isPushData())
        if data == nil {
            return true // OP_N
        }
        if data?.count == 0 {
            return opcode == ScriptOpCodes.OP_0
        }
        if data?.count == 1 {
            let b = data![0]
            if b >= 0x01 && b <= 0x10 {
                return opcode == ScriptOpCodes.OP_1 + Int(b) - 1
            }
            if (b & 0xFF) == 0x81 {
                return opcode == ScriptOpCodes.OP_1NEGATE
            }
        }
        if data!.count < ScriptOpCodes.OP_PUSHDATA1 {
            return opcode == data?.count
        }
        if data!.count < 256 {
            return opcode == ScriptOpCodes.OP_PUSHDATA1
        }
        if data!.count < 65536 {
            return opcode == ScriptOpCodes.OP_PUSHDATA2
        }
        
        // can never be used, but implemented for completeness
        return opcode == ScriptOpCodes.OP_PUSHDATA4
    }
    
    public func write(outData: inout Data) throws {
        if isOpCode() && opcode != ScriptOpCodes.OP_0 {
            if data != nil {
                throw PSBTError.message("Data must be null for opcode chunk")
            }
            outData.append(contentsOf: [UInt8(opcode)])
        } else if let data = data {
            if opcode < ScriptOpCodes.OP_PUSHDATA1 {
                if data.count != opcode {
                    throw PSBTError.message("Data length must equal opcode value")
                }
                outData.append(contentsOf: [UInt8(opcode)])
            } else if opcode == ScriptOpCodes.OP_PUSHDATA1 {
                if data.count > 0xFF {
                    throw PSBTError.message("Data length must be less than or equal to 256")
                }
                outData.append(contentsOf: [UInt8(ScriptOpCodes.OP_PUSHDATA1)])
                let length = UInt8(data.count)
                outData.append(contentsOf: [UInt8(length)])
            } else if opcode == ScriptOpCodes.OP_PUSHDATA2 {
                if data.count > 0xFFFF {
                    throw PSBTError.message("Data length must be less than or equal to 65536")
                }
                outData.append(contentsOf: [UInt8(ScriptOpCodes.OP_PUSHDATA2)])
                let length = UInt16(data.count)
                try Utils.uint16ToDataLE(val: length, outData: &outData)
            } else if opcode == ScriptOpCodes.OP_PUSHDATA4 {
                if data.count > Script.MAX_SCRIPT_ELEMENT_SIZE {
                    throw PSBTError.message("Data length must be less than or equal to \(Script.MAX_SCRIPT_ELEMENT_SIZE)")
                }
                outData.append(contentsOf: [UInt8(ScriptOpCodes.OP_PUSHDATA4)])
                try Utils.uint32ToDataLE(val: data.count, outData: &outData)
            } else {
                throw PSBTError.message("Unimplemented")
            }
            outData.append(contentsOf: data)
        } else {
            outData.append(contentsOf: [UInt8(opcode)])
        }
    }
    
    public func isSignature() -> Bool {
//        guard let data = self.data, !data.isEmpty else {
//            return false
//        }
//        do {
//            try TransactionSignature.decodeFromBitcoin(data: data, requireCanonical: false)
//        } catch {
//            return false
//        }

        return true
    }
    
    public func isScript() -> Bool {
        // Do not attempt to parse long data byte arrays into scripts
        guard let data = self.data, !data.isEmpty, data.count <= 1000 else {
            return false
        }

        if isSignature() || isPubKey() {
            return false
        }
        var script: Script
        do {
            script = try Script(programBytes: data, parse: false)
            try script.parse()
        } catch {
            return false
        }

        // Flaky: Test if contains a non-zero opcode, otherwise not a script
        for chunk in script.getChunks() {
            if chunk.opcode == ScriptOpCodes.OP_0 {
                return true
            }
        }

        return false
    }
    
    public func getScript() throws  -> Script? {
        guard let _data = self.data else {
            return nil
        }
        return try Script(programBytes: _data)
    }
    
    public func isPubKey() -> Bool {
        guard let data = self.data, !data.isEmpty else {
            return false
        }
        return true
//        return ECKey.isPubKeyCanonical(data: data)
    }

    public func getPubKey() -> Data {
        return Data(data!)
//        return ECKey.fromPublicOnly(data: data)
    }
    
    public static func getOpcodeForLength(_ length: Int) -> Int {
        if length == 0 {
            return ScriptOpCodes.OP_0
        }
        if length <= 0xFF {
            return ScriptOpCodes.OP_PUSHDATA1
        }
        if length <= 0xFFFF {
            return ScriptOpCodes.OP_PUSHDATA2
        }
        return ScriptOpCodes.OP_PUSHDATA4
    }
    
    public func getSignature() throws -> TransactionSignature {
        do {
            return try TransactionSignature.decodeFromBitcoin(data: data ?? [UInt8](), requireCanonicalEncoding: false)
        } catch let error {
            throw error
        }
    }
    
    public func toString() -> String {
        guard let _data = data else {
            return "OP_" + ScriptOpCodes.getOpCodeName(opcode: opcode)
        }
        if _data.count == 0 {
            return "OP_0"
        }
        if Utils.isUtf8(bytes: data!) {
            return String(data: Data(_data), encoding: .utf8)!
        }

        return _data.map { String(format: "%02hhx", $0) }.joined()
    }

    public func equals(_ o: Any?) -> Bool {
        guard let other = o as? ScriptChunk else {
            return false
        }
        if let _data = data, let otherData = other.data {
            return opcode == other.opcode && _data == otherData
        } else {
            return opcode == other.opcode
        }
    }
    
    public func hashCode() -> Int {
        var hasher = Hasher()
        hasher.combine(opcode)
        hasher.combine(data.hashValue)
        return hasher.finalize()
    }
}
