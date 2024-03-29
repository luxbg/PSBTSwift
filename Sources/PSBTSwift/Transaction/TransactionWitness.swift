//
//  TransactionWitness.swift
//
//
//  Created by 薛跃杰 on 2024/1/18.
//

import Foundation
import BitcoinSwift

public class TransactionWitness: ChildMessage, Equatable {
    
    public var pushes: [Data]

    public init(transaction: Transaction, signature: Data) {
        self.pushes = []
        super.init()
        pushes.append(signature)
    }

    public init(transaction: Transaction, pubKey: BitcoinKey, signature: Data) {
        self.pushes = []
        super.init()
        pushes.append(signature)
        pushes.append(pubKey.publicKey)
    }

    public init(transaction: Transaction, signatures: [Data], witnessScript: Script) throws {
        self.pushes = []
        super.init()
        if try ScriptType.MULTISIG.isScriptType(script: witnessScript) {
            pushes.append(Data())
        }
        for signature in signatures {
            pushes.append(signature)
        }
        pushes.append(Data(try witnessScript.getProgram()))
    }

    public init(transaction: Transaction) {
        self.pushes = []
        super.init()
    }

    public init(transaction: Transaction, witnesses: [Data]) {
        self.pushes = witnesses
        super.init()
    }
    
    public init(parent: Transaction?, rawtx: [UInt8], offset: Int) {
        self.pushes = []
        super.init(rawtx: rawtx, offset: offset)
        self.parent = parent
    }
    
    public override func parse() throws {
        let pushCount = readVarInt()
        for y in 0..<pushCount {
            let pushSize = readVarInt()
            let push = try readBytes(length: Int(pushSize))
            setPush(i: Int(y), value: Data(push))
        }
    }

    public func setPush(i: Int, value: Data) {
        while i >= pushes.count {
            pushes.append(Data())
        }
        pushes[i] = value
    }

    public func getPushCount() -> Int {
        return pushes.count
    }

    public func getLength() -> Int {
        var length = VarInt(value: Int64(pushes.count)).getSizeInBytes()
        for push in pushes {
            if push.count == 1 && push[0] == 0 {
                length += 1
            } else {
                length += VarInt(value: Int64(push.count)).getSizeInBytes()
                length += push.count
            }
        }
        return length
    }
    
//    func bitcoinSerializeToStream(stream: OutputStream) throws {
//        let varIntPushes = VarInt(value: Int64(pushes.count)).encode()
//        stream.write(varIntPushes, maxLength: varIntPushes.count)
//        for push in pushes {
//            if push.count == 1 && push[0] == 0 {
//                stream.write(push.bytes, maxLength: push.count)
//            } else {
//                let varIntPushLength = VarInt(value: Int64(push.count)).encode()
//                stream.write(varIntPushLength, maxLength: varIntPushLength.count)
//                stream.write(push.bytes, maxLength: push.count)
//            }
//        }
//    }
    
    public override func bitcoinSerializeToData(data: inout Data) throws {
        let varIntPushes = VarInt(value: Int64(pushes.count))
        data.append(contentsOf: varIntPushes.encode())
        for push in pushes {
            if push.count == 1 && push[0] == 0 {
                data.append(contentsOf: push)
            } else {
                let varIntPushLength = VarInt(value: Int64(push.count))
                data.append(contentsOf: varIntPushLength.encode())
                data.append(contentsOf: push)
            }
        }
    }

    public func toByteArray() throws -> Data {
//        let stream = OutputStream.toMemory()
//        stream.open()
        var data = Data()
        do {
            try bitcoinSerializeToData(data: &data)
        } catch let error {
            throw error
        }
        return data
    }
    
    public func toString() -> String {
        var builder = ""
        for push in pushes {
            if push.count == 0 {
                builder.append("NULL")
            } else if push.isEmpty {
                builder.append("EMPTY")
            } else {
                builder.append(push.toHexString())
            }
            builder.append(" ")
        }

        return builder.trimmingCharacters(in: .whitespaces)
    }
    
    public func asScriptChunks() -> [ScriptChunk] {
        var scriptChunks = [ScriptChunk]()
        for push in pushes {
            scriptChunks.append(ScriptChunk(opcode: ScriptChunk.getOpcodeForLength(push.count), data: push.bytes))
        }
        return scriptChunks
    }

    public func getSignatures() throws -> [TransactionSignature] {
        var signatures = [TransactionSignature]()
        let scriptChunks = self.asScriptChunks()
        for chunk in scriptChunks {
            if chunk.isSignature() {
                signatures.append(try chunk.getSignature())
            }
        }
        return signatures
    }

    public func getWitnessScript() throws -> Script? {
        let scriptChunks = self.asScriptChunks()
        if !scriptChunks.isEmpty && scriptChunks.last!.isScript() {
            return try scriptChunks.last!.getScript()
        }
        return nil
    }

    public func equals(_ o: Any?) -> Bool {
        guard let other = o as? TransactionWitness else {
            return false
        }
        if pushes.count != other.pushes.count {
            return false
        }
        for i in 0..<pushes.count {
            if pushes[i] != other.pushes[i] {
                return false
            }
        }
        return true
    }

    public func hashCode() -> Int {
        var hashCode = 1
        for push in pushes {
            hashCode = 31 * hashCode + push.hashValue
        }
        return hashCode
    }
    
    public static func == (lhs: TransactionWitness, rhs: TransactionWitness) -> Bool {
        return lhs.pushes == rhs.pushes
    }
}
