//
//  TransactionInput.swift
//
//
//  Created by 薛跃杰 on 2024/1/18.
//

import Foundation

public class TransactionInput: ChildMessage, Equatable {
    
    public static let SEQUENCE_LOCKTIME_DISABLED: UInt64 = 4294967295
    public static let SEQUENCE_RBF_ENABLED: UInt64 = 4294967293
    public static let MAX_RELATIVE_TIMELOCK: UInt64 = 2147483647
    public static let RELATIVE_TIMELOCK_VALUE_MASK: UInt64 = 0xFFFF
    public static let RELATIVE_TIMELOCK_TYPE_FLAG: UInt64 = 0x400000
    public static let RELATIVE_TIMELOCK_SECONDS_INCREMENT: Int = 512

    // Allows for altering transactions after they were broadcast. Values below NO_SEQUENCE-1 mean it can be altered.
    public var sequence: UInt64?

    // Data needed to connect to the output of the transaction we're gathering coins from.
    public var outpoint: TransactionOutPoint?

    public var scriptBytes: [UInt8]

    public var scriptSig: Script?

    public var witness: TransactionWitness?
    
    public convenience init(transaction: Transaction, outpoint: TransactionOutPoint, scriptBytes: [UInt8]) {
        self.init(transaction: transaction, outpoint: outpoint, scriptBytes: scriptBytes, witness: nil)
    }

    public init(transaction: Transaction, outpoint: TransactionOutPoint, scriptBytes: [UInt8] = [UInt8](), witness: TransactionWitness?) {
        self.sequence = TransactionInput.SEQUENCE_LOCKTIME_DISABLED
        self.outpoint = outpoint
        self.scriptBytes = scriptBytes
        self.witness = witness
        super.init()
        self.length = 40 + (scriptBytes.isEmpty ? 1 : VarInt.sizeOf(Int64(scriptBytes.count)) + scriptBytes.count)
        if let witness = witness {
            transaction.adjustLength(adjustment: witness.getLength())
        }
    }
    
    public init(transaction: Transaction, rawtx: [UInt8], offset: Int) {
        self.scriptBytes = [UInt8]()
        super.init(rawtx: rawtx, offset: offset)
        self.setParent(parent: transaction)
     }
    
    public override func parse() throws {
        outpoint = try TransactionOutPoint(rawtx: payload ?? [UInt8](), offset: cursor, parent: self)
        cursor += try outpoint!.getMessageSize()
        let scriptLen = readVarInt()
        length = cursor - offset + Int(scriptLen) + 4
        scriptBytes = try readBytes(length: Int(scriptLen))
        sequence = UInt64(readUint32())
    }
    
    public func getScriptSig() throws -> Script {
        if let _scriptSig = scriptSig {
            return _scriptSig
        } else {
            if isCoinBase() {
                //ScriptSig may be invalid, attempt to parse
                scriptSig = try Script(programBytes: scriptBytes, parse: false)
                do {
                    try scriptSig!.parse()
                } catch {
                    scriptSig = Script(chunks: scriptSig!.getChunks())
                }
                return scriptSig!
            } else {
                scriptSig = try Script(programBytes: scriptBytes)
                return scriptSig!
            }
        }
    }

    public func setScriptBytes(scriptBytes: [UInt8]) {
        super.payload = nil
        self.scriptSig = nil
        let oldLength = length
        self.scriptBytes = scriptBytes
        // 40 = previous_outpoint (36) + sequence (4)
        let newLength = 40 + (scriptBytes.isEmpty ? 1 : VarInt.sizeOf(Int64(scriptBytes.count)) + scriptBytes.count)
        adjustLength(adjustment: newLength - oldLength)
    }
    
    public func clearScriptBytes() {
        setScriptBytes(scriptBytes: [UInt8]())
    }

    func witness(witness: TransactionWitness?) {
        self.witness = witness
    }

    public func setWitness(witness: TransactionWitness?) {
        let newLength = witness != nil ? witness!.getLength() : 0
        let existingLength = witness != nil ? witness!.getLength() : 0
        if let _parent = parent {
            _parent.adjustLength(adjustment: newLength - existingLength)
        }

        self.witness = witness
    }
    
    public func hasWitness() -> Bool {
        return witness != nil
    }

    public func setSequenceNumber(sequence: UInt64) {
        self.sequence = sequence
    }

    public func getIndex() -> Int {
        guard let transaction = parent as? Transaction else {
            return -1
        }
        return transaction.inputs.firstIndex(of: self) ?? -1
    }

    public func isCoinBase() -> Bool {
        return outpoint!.hashData == Data(repeating: UInt8(0), count: 32) &&
        outpoint!.index & 0xFFFFFFFF == 0xFFFFFFFF
    }
    
    public func isReplaceByFeeEnabled() -> Bool {
        return sequence ?? 0 <= TransactionInput.SEQUENCE_RBF_ENABLED
    }

    public func isAbsoluteTimeLockDisabled() -> Bool {
        return sequence ?? 0 >= TransactionInput.SEQUENCE_LOCKTIME_DISABLED
    }

    public func isAbsoluteTimeLocked() -> Bool {
        return !isAbsoluteTimeLockDisabled() && !isRelativeTimeLocked()
    }

    public func isRelativeTimeLocked() -> Bool {
        return getTransaction().isRelativeLocktimeAllowed() && sequence ?? 0 <= TransactionInput.MAX_RELATIVE_TIMELOCK
    }

    public func isRelativeTimeLockedInBlocks() -> Bool {
        return isRelativeTimeLocked() && ((sequence ?? 0 & TransactionInput.RELATIVE_TIMELOCK_TYPE_FLAG) == 0)
    }

    public func getRelativeLocktime() -> UInt64 {
        return sequence ?? 0 & TransactionInput.RELATIVE_TIMELOCK_VALUE_MASK
    }

    public func getTransaction() -> Transaction {
        return parent as! Transaction
    }

    public override func bitcoinSerializeToData(data: inout Data) throws {
        guard let _outpoint = outpoint else {
            throw PSBTError.message("Transaction bitcoinSerialize output nil")
        }
        try _outpoint.bitcoinSerializeToData(data: &data)
        let varInt = VarInt(value: Int64(scriptBytes.count))
        data.append(contentsOf: varInt.encode())
        data.append(contentsOf: scriptBytes)
        try Utils.uint32ToDataLE(val: Int(sequence ?? 0), outData: &data)
    }
    
    public static func == (lhs: TransactionInput, rhs: TransactionInput) -> Bool {
        return lhs.sequence == rhs.sequence && lhs.outpoint == rhs.outpoint && lhs.scriptBytes == rhs.scriptBytes && lhs.witness! == rhs.witness!
    }
}
