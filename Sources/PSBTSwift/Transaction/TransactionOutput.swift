//
//  TransactionOutput.swift
//
//
//  Created by 薛跃杰 on 2024/1/18.
//

import Foundation
import CryptoSwift

public class TransactionOutput: ChildMessage, Equatable {
    public var value: Int64
    public var scriptBytes: [UInt8]
    public var script: Script?

    private var addresses = [Address]()

    public convenience init(transaction: Transaction, value: Int64, script: Script) throws {
        self.init(transaction: transaction, value: value, scriptBytes: try script.getProgram())
    }

    public init(transaction: Transaction, value: Int64, scriptBytes: [UInt8]) {
        self.value = value
        self.scriptBytes = scriptBytes
        super.init()
        setParent(parent: transaction)
        length = 8 + VarInt.sizeOf(Int64(scriptBytes.count)) + scriptBytes.count
    }

    public init(parent: Transaction?, rawtx: [UInt8], offset: Int) {
        self.value = 0
        self.scriptBytes = [UInt8]()
        super.init(rawtx: rawtx, offset: offset)
        setParent(parent: parent)
    }

    public override func parse() throws {
        value = readInt64()
        let scriptLen = Int(readVarInt())
        length = cursor - offset + scriptLen
        scriptBytes = try readBytes(length: scriptLen)
        script = try getScript()
    }

    public func bitcoinSerialize()throws -> [UInt8] {
        var outputData = Data()
        try bitcoinSerializeToData(data: &outputData)
        return outputData.bytes
    }
    
    public override func bitcoinSerializeToData(data: inout Data) throws {
        Utils.int64ToDataLE(val: value, data: &data)
        data.append(contentsOf: VarInt(value: Int64(scriptBytes.count)).encode())
        data.append(contentsOf: scriptBytes)
    }

    public func getScript() throws -> Script {
        if script == nil {
            script = try Script(programBytes: scriptBytes)
        }

        return script!
    }

    public func getHash() throws -> Data {
        let transaction = parent as! Transaction
        return try transaction.getTxId()
    }

    public func getIndex() -> Int {
        let transaction = parent as! Transaction
        return transaction.outputs.firstIndex(of: self)!
    }
    
    public static func == (lhs: TransactionOutput, rhs: TransactionOutput) -> Bool {
        return lhs.value == rhs.value && lhs.scriptBytes == rhs.scriptBytes
    }
}
