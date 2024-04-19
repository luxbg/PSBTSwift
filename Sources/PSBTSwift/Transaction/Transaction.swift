//
//  Transaction.swift
//
//
//  Created by 薛跃杰 on 2024/1/12.
//

import Foundation
import CryptoSwift
import BigInt
//import BitcoinSwift

public class Transaction: ChildMessage {
    public static let MAX_BLOCK_SIZE = 1000 * 1000
    public static let MAX_BITCOIN = 21 * 1000 * 1000
    public static let SATOSHIS_PER_BITCOIN = 100 * 1000 * 1000
    public static let MAX_BLOCK_LOCKTIME = 500000000
    public static let WITNESS_SCALE_FACTOR = 4
    public static let DEFAULT_SEGWIT_FLAG = 1
    public static let COINBASE_MATURITY_THRESHOLD = 100
    
    public static let DUST_RELAY_TX_FEE = 3.0
    
    // Default min feerate, defined in sats/vByte
    public static let DEFAULT_MIN_RELAY_FEE = 1.0
    
    public static let LEAF_VERSION_TAPSCRIPT: UInt8 = 0xc0
    
    public var version: Int64
    public var locktime: Int64
    public var segwit: Bool
    public var segwitFlag: Int
    
    public var cachedTxId: Data?
    public var cachedWTxId: Data?
    
    public var inputs: [TransactionInput]
    public var outputs: [TransactionOutput]
    
    public override init() {
        version = 1
        inputs = []
        outputs = []
        locktime = 0
        segwit = false
        segwitFlag = 0
        super.init()
        length = 8
    }

    public init(rawtx: [UInt8]) {version = 1
        inputs = []
        outputs = []
        locktime = 0
        segwit = false
        segwitFlag = 0
        super.init(rawtx: rawtx, offset: 0)
    }

    public func setVersion(version: Int64) {
        self.version = version
    }

    public func setLocktime(locktime: Int64) {
        self.locktime = locktime
    }

    public func isLocktimeEnabled() -> Bool {
        if locktime == 0 { return false }
        return isLocktimeSequenceEnabled()
    }
    
    public func isLocktimeSequenceEnabled() -> Bool {
        for input in inputs {
            if !input.isAbsoluteTimeLockDisabled() {
                return true
            }
        }
        return false
    }

    public func isRelativeLocktimeAllowed() -> Bool {
        return version >= 2
    }

    public func isReplaceByFee() -> Bool {
        for input in inputs {
            if input.isReplaceByFeeEnabled() {
                return true
            }
        }
        return false
    }

    public func getTxId() throws -> Data {
        if cachedTxId == nil {
            if !hasWitnesses() && cachedWTxId != nil {
                cachedTxId = cachedWTxId
            } else {
                cachedTxId = try calculateTxId(useWitnesses: false)
            }
        }
        return cachedTxId!
    }

    public func getWTxId() throws -> Data {
        if cachedWTxId == nil {
            if !hasWitnesses() && cachedTxId != nil {
                cachedWTxId = cachedTxId
            } else {
                cachedWTxId = try calculateTxId(useWitnesses: true)
            }
        }
        return cachedWTxId!
    }
    
    public func calculateTxId(useWitnesses: Bool) throws -> Data {
        var data = Data()
        do {
            try bitcoinSerializeToData(data: &data, useWitnessFormat: useWitnesses)
        } catch {
            throw  PSBTError.message("Unexpected error: \(error).")
        }
        return Data(data.sha256().sha256().reversed())
    }

    public func isSegwit() -> Bool {
        return segwit
    }

    public func setSegwitFlag(segwitFlag: Int) {
        if !segwit {
            adjustLength(adjustment: 2)
            segwit = true
        }
        self.segwitFlag = segwitFlag
    }

    public func clearSegwit() {
        if segwit {
            adjustLength(adjustment: -2)
            segwit = false
        }
    }
    
    public func hasScriptSigs() -> Bool {
        for input in inputs {
            if !input.scriptBytes.isEmpty {
                return true
            }
        }
        return false
    }

    public func hasWitnesses() -> Bool {
        for input in inputs {
            if input.hasWitness() {
                return true
            }
        }
        return false
    }

    public func bitcoinSerialize() throws -> [UInt8] {
        let useWitnessFormat = isSegwit()
        return try bitcoinSerialize(useWitnessFormat: useWitnessFormat)
    }

    public func bitcoinSerialize(useWitnessFormat: Bool) throws -> [UInt8] {
        var data = Data()
        do {
            try bitcoinSerializeToData(data: &data, useWitnessFormat: useWitnessFormat)
        } catch let error {
            throw error
        }
        return data.bytes
    }
    
    public func bitcoinSerializeToData(_ data: inout Data) throws {
        let useWitnessFormat = isSegwit()
        do {
            try bitcoinSerializeToData(data: &data, useWitnessFormat: useWitnessFormat)
        } catch let error {
            throw error
        }
    }
    
    public func bitcoinSerializeToData(data: inout Data, useWitnessFormat: Bool) throws {
        // version
        try Utils.uint32ToDataLE(val: Int(version), outData: &data)

        // marker, flag
        if useWitnessFormat {
            data.append(0)
            data.append(UInt8(segwitFlag))
        }

        // txin_count, txins
        let varIntInputs = VarInt(value: Int64(inputs.count))
        let inputData = varIntInputs.encode()
        data.append(contentsOf: inputData)
        for input in inputs {
            try input.bitcoinSerializeToData(data: &data)
        }

        // txout_count, txouts
        let varIntOutputs = VarInt(value: Int64(outputs.count))
        let outputData = varIntOutputs.encode()
        data.append(contentsOf: outputData)
        
        for output in outputs {
            try output.bitcoinSerializeToData(data: &data)
        }

        // script_witnesses
        if useWitnessFormat {
            for input in inputs {
                // Per BIP141 all txins must have a witness
                if !input.hasWitness() {
                    input.setWitness(witness: TransactionWitness(transaction: self))
                }

                try input.witness?.bitcoinSerializeToData(data: &data)
            }
        }

        // lock_time
        try Utils.uint32ToDataLE(val: Int(locktime), outData: &data)
    }
    
    public override func parse() throws {
        // version
        version = Int64(readUint32())

        // peek at marker
        let marker = payload?[cursor]
        segwit = (marker == 0)

        // marker, flag
        if segwit {
            let segwitHeader = try readBytes(length: 2)
            segwitFlag = Int(segwitHeader[1])
        }

        // txin_count, txins
        parseInputs()

        // txout_count, txouts
        parseOutputs()

        // script_witnesses
        if segwit {
            parseWitnesses()
        }

        // lock_time
        locktime = Int64(readUint32())

        length = cursor - offset
    }

    private func parseInputs() {
        let numInputs = readVarInt()
        inputs = [TransactionInput](repeating: TransactionInput(transaction: self, rawtx: payload!, offset: cursor), count: min(Int(numInputs), Utils.MAX_INITIAL_ARRAY_LENGTH))
        for i in 0..<numInputs {
            let input = TransactionInput(transaction: self, rawtx: payload!, offset: cursor)
            inputs[Int(i)] = input
            let scriptLen = readVarInt(offset: TransactionOutPoint.MESSAGE_LENGTH)
            cursor += Int(scriptLen) + 4
        }
    }

    private func parseOutputs() {
        let numOutputs = readVarInt()
        outputs = [TransactionOutput](repeating:TransactionOutput(parent: self, rawtx: payload!, offset: cursor), count: min(Int(numOutputs), Utils.MAX_INITIAL_ARRAY_LENGTH))
        for i in 0..<numOutputs {
            let output = TransactionOutput(parent: self, rawtx: payload!, offset: cursor)
            outputs[Int(i)] = output
            let scriptLen = readVarInt(offset: 8)
            cursor += Int(scriptLen)
        }
    }
    
    private func parseWitnesses() {
        let numWitnesses = inputs.count
        for i in 0..<numWitnesses {
            let witness = TransactionWitness(parent: self, rawtx: payload!, offset: cursor)
            inputs[i].witness = witness
            cursor += witness.getLength()
        }
    }

    public func getSize() -> Int {
        return length
    }

    public func getVirtualSize() -> Double {
        return Double(getWeightUnits()) / Double(Transaction.WITNESS_SCALE_FACTOR)
    }

    public func getWeightUnits() -> Int {
        var wu = 0

        // version
        wu += 4 * Transaction.WITNESS_SCALE_FACTOR
        // marker, flag
        if isSegwit() {
            wu += 2
        }
        // txin_count, txins
        wu += VarInt(value: Int64(inputs.count)).getSizeInBytes() * Transaction.WITNESS_SCALE_FACTOR
        for input in inputs {
            wu += input.length * Transaction.WITNESS_SCALE_FACTOR
        }
        // txout_count, txouts
        wu += VarInt(value: Int64(outputs.count)).getSizeInBytes() * Transaction.WITNESS_SCALE_FACTOR
        for output in outputs {
            wu += output.length * Transaction.WITNESS_SCALE_FACTOR
        }
        // script_witnesses
        if isSegwit() {
            for input in inputs {
                if input.hasWitness() {
                    wu += input.witness!.getLength()
                }
            }
        }
        // lock_time
        wu += 4 * Transaction.WITNESS_SCALE_FACTOR

        return wu
    }

    public func addInput(spendTxHash: Data, outputIndex: Int, script: Script) throws -> TransactionInput {
        if isSegwit() {
            return try addInput(spendTxHash: spendTxHash, outputIndex: outputIndex, script: script, witness: TransactionWitness(transaction: self))
        } else {
            return addInput(TransactionInput(transaction: self, outpoint: TransactionOutPoint(hash: spendTxHash, index: UInt64(outputIndex)), scriptBytes: try script.getProgram()))
        }
    }

    public func addInput(spendTxHash: Data,
                         outputIndex: Int,
                         script: Script,
                         witness: TransactionWitness) throws -> TransactionInput {
        if !isSegwit() {
            setSegwitFlag(segwitFlag: Transaction.DEFAULT_SEGWIT_FLAG)
        }
        return addInput(TransactionInput(transaction: self,
                                         outpoint: TransactionOutPoint(hash: spendTxHash, index: UInt64(outputIndex)),
                                         scriptBytes: try script.getProgram(),
                                         witness: witness))
    }

    public func addInput(_ input: TransactionInput) -> TransactionInput {
        input.setParent(parent: self)
        inputs.append(input)
        adjustLength(newArraySize: inputs.count, adjustment: input.length)
        return input
    }

    public func shuffleOutputs() {
        outputs.shuffle()
    }

    public func addOutput(value: Int64, script: Script) throws -> TransactionOutput {
        return addOutput(try TransactionOutput(transaction: self, value: value, script: script))
    }

    public func addOutput(value: Int64, address: Address) throws -> TransactionOutput {
        return addOutput(try TransactionOutput(transaction: self, value: value, script: try address.getOutputScript()!))
    }

    public func addOutput(value: Int64, pubkey: Data) throws -> TransactionOutput {
        return addOutput(try TransactionOutput(transaction: self, value: value, script: try! ScriptType.P2PK.getOutputScript(publicKey: pubkey)))
    }

    public func addOutput(_ output: TransactionOutput) -> TransactionOutput {
        output.setParent(parent: self)
        outputs.append(output)
        adjustLength(newArraySize: outputs.count, adjustment: output.length)
        return output
    }

    public func verify() throws {
        if inputs.isEmpty || outputs.isEmpty {
            throw PSBTError.message("VerificationException.EmptyInputsOrOutputs")
        }
        if try self.getMessageSize() > Transaction.MAX_BLOCK_SIZE {
            throw PSBTError.message("VerificationException.LargerThanMaxBlockSize")
        }

        var outpoints = Set<TransactionOutPoint>()
        for input in inputs {
            if outpoints.contains(input.outpoint!) {
                throw PSBTError.message("VerificationException.DuplicatedOutPoint")
            }
            outpoints.insert(input.outpoint!)
        }

        var valueOut: Int64 = 0
        for output in outputs {
            let value = output.value
            if value < 0 {
                throw PSBTError.message("VerificationException.NegativeValueOutput")
            }
            let (sum, overflow) = valueOut.addingReportingOverflow(valueOut)
            if overflow {
                throw PSBTError.message("VerificationException.ExcessiveValue")
            } else {
                valueOut = sum
            }
            let bitcoin = Int(value) / Transaction.SATOSHIS_PER_BITCOIN
            if bitcoin > Transaction.MAX_BITCOIN {
                throw PSBTError.message("VerificationException.ExcessiveValue")
            }
        }

        if isCoinBase() {
            if inputs[0].scriptBytes.count < 2 || inputs[0].scriptBytes.count > 100 {
                throw PSBTError.message("VerificationException.CoinbaseScriptSizeOutOfRange")
            }
        } else {
            for input in inputs {
                if input.isCoinBase() {
                    throw PSBTError.message("VerificationException.UnexpectedCoinbaseInput")
                }
            }
        }
    }
    
    public func isCoinBase() -> Bool {
        return inputs.count == 1 && inputs[0].isCoinBase()
    }

    public static func isTransaction(bytes: [UInt8]) -> Bool {
        //Incomplete quick test
        if bytes.isEmpty {
            return false
        }
        let version = Utils.readUint32( bytes: bytes, offset: 0)
        return version > 0 && version < 5
    }

    public func hashForLegacySignature(inputIndex: Int, redeemScript: Script, sigHash: SigHash) throws -> Data {
        return try hashForLegacySignature(inputIndex: inputIndex, connectedScript: redeemScript.getProgram(), sigHashType: sigHash.rawValue)
    }

    public func hashForLegacySignature(inputIndex: Int, connectedScript: [UInt8], sigHashType: UInt8) throws -> Data {
        do {
            var conScript = connectedScript
            var baos = Data()
            try self.bitcoinSerializeToData(&baos)
            let tx = Transaction(rawtx: baos.bytes)

            for i in 0..<tx.inputs.count {
                tx.inputs[i].clearScriptBytes()
            }

            conScript = Script.removeAllInstancesOfOp(conScript, ScriptOpCodes.OP_CODESEPARATOR)
            let input = tx.inputs[inputIndex]
            tx.inputs[inputIndex].setScriptBytes(scriptBytes: conScript)

            if (sigHashType & 0x1f) == SigHash.NONE.rawValue {
                tx.outputs = []
                for i in 0..<tx.inputs.count {
                    if i != inputIndex {
                        tx.inputs[i].setSequenceNumber(sequence: 0)
                    }
                }
            } else if (sigHashType & 0x1f) == SigHash.SINGLE.rawValue {
                // SIGHASH_SINGLE means only sign the output at the same index as the input (ie, my output).
                if inputIndex >= tx.outputs.count {
                    return Data(hex: "0100000000000000000000000000000000000000000000000000000000000000")
                }
                tx.outputs = Array(tx.outputs[0...inputIndex])
                for i in 0..<inputIndex {
                    tx.outputs[i] = TransactionOutput(transaction: tx, value: -1, scriptBytes: [])
                }
                // The signature isn't broken by new versions of the transaction issued by other parties.
                for i in 0..<tx.inputs.count {
                    if i != inputIndex {
                        tx.inputs[i].setSequenceNumber(sequence: 0)
                    }
                }
            }

            if (sigHashType & SigHash.ANYONECANPAY.rawValue) == SigHash.ANYONECANPAY.rawValue {
                tx.inputs = []
                tx.inputs.append(input)
            }
            var data = Data()
            try tx.bitcoinSerializeToData(data: &data, useWitnessFormat: false)
            // We also have to write a hash type (sigHashType is actually an unsigned char)
            try Utils.uint32ToDataLE(val: 0x000000ff & Int(sigHashType), outData: &data)
            let hash = data.sha256().sha256()
            return hash
        } catch {
            throw PSBTError.message("IOException: \(error)")
        }
    }
    
    public func hashForWitnessSignature(inputIndex: Int, scriptCode: Script, prevValue: Int64, sigHash: SigHash) throws -> Data {
        return try hashForWitnessSignature(inputIndex: inputIndex, scriptCode: try scriptCode.getProgram(), prevValue: prevValue, sigHashType:sigHash.rawValue)
    }
    
    public func hashForWitnessSignature(inputIndex: Int, scriptCode: [UInt8], prevValue: Int64, sigHashType: UInt8) throws -> Data {
        var hashPrevouts = [UInt8](repeating: 0, count: 32)
        var hashSequence = [UInt8](repeating: 0, count: 32)
        var hashOutputs = [UInt8](repeating: 0, count: 32)
        let basicSigHashType = sigHashType & 0x1f
        let anyoneCanPay = (sigHashType & SigHash.ANYONECANPAY.rawValue) == SigHash.ANYONECANPAY.rawValue
        let signAll = (basicSigHashType != SigHash.SINGLE.rawValue) && (basicSigHashType != SigHash.NONE.rawValue)

        if !anyoneCanPay {
            var bosHashData = Data()
            for i in 0..<self.inputs.count {
                bosHashData.append(Data(self.inputs[i].outpoint!.hashData.reversed()))
                try Utils.uint32ToDataLE(val: Int(self.inputs[i].outpoint!.index), outData: &bosHashData)
            }
            hashPrevouts = bosHashData.sha256().sha256().bytes
        }

        if !anyoneCanPay && signAll {
            var bosSequenceData = Data()
            for i in 0..<self.inputs.count {
                try Utils.uint32ToDataLE(val: Int(self.inputs[i].sequence!), outData: &bosSequenceData)
            }
            hashSequence = bosSequenceData.sha256().sha256().bytes
        }

        if signAll {
            var bosHashOutputsData = Data()
            for i in 0..<self.outputs.count {
                try Utils.uint64ToDataLE(val: BigInt(self.outputs[i].value), data: &bosHashOutputsData)
                bosHashOutputsData.append(contentsOf: VarInt(value: Int64(self.outputs[i].scriptBytes.count)).encode())
                bosHashOutputsData.append(contentsOf: self.outputs[i].scriptBytes)
            }
            hashOutputs = bosHashOutputsData.sha256().sha256().bytes
        } else if basicSigHashType == SigHash.SINGLE.rawValue && inputIndex < outputs.count {
            var bosHashOutputsData = Data()
            try Utils.uint64ToDataLE(val: BigInt(self.outputs[inputIndex].value), data: &bosHashOutputsData)
            bosHashOutputsData.append(contentsOf: VarInt(value: Int64(self.outputs[inputIndex].scriptBytes.count)).encode())
            bosHashOutputsData.append(contentsOf: self.outputs[inputIndex].scriptBytes)
            hashOutputs = bosHashOutputsData.sha256().sha256().bytes
        }
        var bosData = Data()
        try Utils.uint32ToDataLE(val: Int(version), outData: &bosData)
        bosData.append(contentsOf: hashPrevouts)
        bosData.append(contentsOf: hashSequence)
        bosData.append(contentsOf: inputs[inputIndex].outpoint!.hashData.reversed())
        try Utils.uint32ToDataLE(val: Int(inputs[inputIndex].outpoint!.index), outData: &bosData)
        let scriptLength = VarInt(value: Int64(scriptCode.count))
        bosData.append(contentsOf: scriptLength.encode())
        bosData.append(contentsOf: scriptCode)
        try Utils.uint64ToDataLE(val: BigInt(prevValue), data: &bosData)
        try Utils.uint32ToDataLE(val: Int(inputs[inputIndex].sequence!), outData: &bosData)
        bosData.append(contentsOf: hashOutputs)
        try Utils.uint32ToDataLE(val: Int(self.locktime), outData: &bosData)
        try Utils.uint32ToDataLE(val: 0x000000ff & Int(sigHashType), outData: &bosData)
        return bosData.sha256().sha256()
    }

    public func hashForTaprootSignature(spentUtxos: [TransactionOutput?], inputIndex: Int, scriptPath: Bool, script: Script, sigHash: SigHash, annex: [UInt8]?) throws -> Data {
        return try hashForTaprootSignature(spentUtxos: spentUtxos, inputIndex: inputIndex, scriptPath: scriptPath, script: script, sigHashType: sigHash.rawValue, annex: annex)
    }

    public func hashForTaprootSignature(spentUtxos: [TransactionOutput?], inputIndex: Int, scriptPath: Bool, script: Script, sigHashType: UInt8, annex: [UInt8]?) throws -> Data {
        if spentUtxos.count != inputs.count {
            throw PSBTError.message("Provided spent UTXOs length does not equal the number of transaction inputs")
        }
        try spentUtxos.forEach { transactionOutput in
            guard let _ = transactionOutput else {
                throw PSBTError.message("Not all spent UTXOs are provided")
            }
        }
        if inputIndex >= inputs.count {
            throw PSBTError.message("Input index is greater than the number of transaction inputs")
        }
        
        var bosData = Data()
        let outType = sigHashType == 0x00 ? SigHash.ALL.rawValue : (sigHashType & 0x03)
        let anyoneCanPay = (sigHashType & SigHash.ANYONECANPAY.rawValue) == SigHash.ANYONECANPAY.rawValue
        
        bosData.append(contentsOf: [UInt8(0x00)])
        bosData.append(contentsOf: [sigHashType])
        try Utils.uint32ToDataLE(val: Int(self.version), outData: &bosData)
        try Utils.uint32ToDataLE(val: Int(self.locktime), outData: &bosData)

        if !anyoneCanPay {
            var outpointsData = Data()
            var outputValuesData = Data()
            var outputScriptPubKeysData = Data()
            var inputSequencesData = Data()
            for i in 0..<inputs.count {
                let input = inputs[i]
                try input.outpoint!.bitcoinSerializeToData(data: &outpointsData)
                try Utils.uint64ToDataLE(val: BigInt(spentUtxos[i]!.value), data: &outputValuesData)
                byteArraySerialize(bytes: spentUtxos[i]!.scriptBytes, outData: &outputScriptPubKeysData)
                try Utils.uint32ToDataLE(val: Int(input.sequence ?? 0), outData: &inputSequencesData)
            }
            bosData.append(contentsOf: outpointsData.sha256().bytes)
            bosData.append(contentsOf: outputValuesData.sha256().bytes)
            bosData.append(contentsOf: outputScriptPubKeysData.sha256().bytes)
            bosData.append(contentsOf: inputSequencesData.sha256().bytes)
        }
        
        if outType == SigHash.ALL.rawValue {
            var outputData = Data()
            for output in outputs {
                try output.bitcoinSerializeToData(data: &outputData)
            }
            bosData.append(contentsOf: outputData.bytes.sha256())
        }

        var spendType: UInt8 = 0x00
        if annex != nil {
            spendType |= 0x01
        }
        if scriptPath {
            spendType |= 0x02
        }
        bosData.append(contentsOf: [spendType])

        if anyoneCanPay {
            try inputs[inputIndex].outpoint!.bitcoinSerializeToData(data: &bosData)
            Utils.int64ToDataLE(val: spentUtxos[inputIndex]!.value, data: &bosData)
            byteArraySerialize(bytes: spentUtxos[inputIndex]!.scriptBytes, outData: &bosData)
            try Utils.uint32ToDataLE(val: Int(inputs[inputIndex].sequence!), outData: &bosData)
        } else {
            try Utils.uint32ToDataLE(val: Int(inputIndex), outData: &bosData)
        }

        if (spendType & 0x01) != 0 {
            var annexData = Data()
            byteArraySerialize(bytes: annex ?? [0], outData: &annexData)
            bosData.append(contentsOf: annexData.sha256().bytes)
        }

        if outType == SigHash.SINGLE.rawValue {
            if inputIndex < outputs.count {
                let sha256Bytes = try outputs[inputIndex].bitcoinSerialize().sha256()
                bosData.append(contentsOf: sha256Bytes)
            } else {
                let sha256Bytes = [UInt8](repeating: UInt8(0), count: 32)
                bosData.append(contentsOf: sha256Bytes)
            }
        }

        if scriptPath {
            var leafData = Data()
            leafData.append(contentsOf: [Transaction.LEAF_VERSION_TAPSCRIPT])
            byteArraySerialize(bytes: try script.getProgram(), outData: &leafData)
            let taggedHash = Utils.taggedHash(tag: "TapLeaf", msg: leafData.bytes)
            bosData.append(contentsOf: taggedHash)
            bosData.append(contentsOf: [0x00])
            try Utils.uint32ToDataLE(val: -1, outData: &bosData)
        }
        let requiredLength = 175 - (anyoneCanPay ? 49 : 0) - (outType != SigHash.ALL.rawValue && outType != SigHash.SINGLE.rawValue ? 32 : 0) + (annex != nil ? 32 : 0) + (scriptPath ? 37 : 0)
        if bosData.count != requiredLength {
            throw PSBTError.message("Invalid message length, was \(bosData.count) not \(requiredLength)")
        }
        return Data(Utils.taggedHash(tag: "TapSighash", msg:bosData.bytes))
    }
    
    private func byteArraySerialize(bytes: [UInt8], outData: inout Data) {
        let varInt = VarInt(value: Int64(bytes.count))
        outData.append(contentsOf: varInt.encode())
        outData.append(contentsOf: bytes)
    }

    public func moveInput(fromIndex: Int, toIndex: Int) {
        moveItem(list: &inputs, fromIndex: fromIndex, toIndex: toIndex)
    }

    public func moveOutput(fromIndex: Int, toIndex: Int) {
        moveItem(list: &outputs, fromIndex: fromIndex, toIndex: toIndex)
    }

    private func moveItem<T>(list: inout [T], fromIndex: Int, toIndex: Int) {
        if fromIndex < 0 || fromIndex >= list.count || toIndex < 0 || toIndex >= list.count {
            fatalError("Invalid indices [\(fromIndex), \(toIndex)] provided to list of size \(list.count)")
        }

        let item = list.remove(at: fromIndex)
        list.insert(item, at: toIndex)

        cachedTxId = nil
        cachedWTxId = nil
    }
}
