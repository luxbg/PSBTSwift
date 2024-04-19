//
//  PSBT.swift
//
//
//  Created by 薛跃杰 on 2024/1/25.
//

import Foundation
//import BitcoinSwift
import Base58Swift
import NIOCore

public class PSBT {
    public static let PSBT_GLOBAL_UNSIGNED_TX: UInt8 = 0x00
    public static let PSBT_GLOBAL_BIP32_PUBKEY: UInt8 = 0x01
    public static let PSBT_GLOBAL_VERSION: UInt8 = 0xfb
    public static let PSBT_GLOBAL_PROPRIETARY: UInt8 = 0xfc

    public static let PSBT_MAGIC_HEX = "70736274"
    public static let PSBT_MAGIC_INT = 1886610036

    public static let STATE_GLOBALS = 1
    public static let STATE_INPUTS = 2
    public static let STATE_OUTPUTS = 3
    public static let STATE_END = 4

    public var inputs = 0
    public var outputs = 0

    public var psbtBytes: [UInt8]?

    public var transaction: Transaction? = nil
    public var version: Int? = nil
    public var extendedPublicKeys = [ExtendedKey: KeyDerivation]()
    public var globalProprietary = [String: String]()

    public var psbtInputs = [PSBTInput]()
    public var psbtOutputs = [PSBTOutput]()
    
    public init(transaction: Transaction) {
        self.transaction = transaction

        for i in 0..<transaction.inputs.count {
            psbtInputs.append(PSBTInput(psbt: self, transaction: transaction, index: i))
        }

        for _ in 0..<transaction.outputs.count {
            psbtOutputs.append(PSBTOutput())
        }
    }
    
//    public init(wallettransaction: WalletTransaction) {
//        
//    }
//    
//    public init(walletTransaction: WalletTransaction, version: Int?, includeGlobalXpubs: Bool) throws {
//        guard let _transaction = try? Transaction(rawtx: walletTransaction.transaction.bitcoinSerialize()) else {
//            throw PSBTError.message("invalid walletTransaction")
//        }
//        _transaction.clearSegwit()
//        for input in _transaction.inputs {
//            input.clearScriptBytes()
//            input.witness = nil
//        }
//        _transaction.shuffleOutputs()
//        
//        if includeGlobalXpubs {
////            for(Keystore keystore : walletTransaction.getWallet().getKeystores()) {
////                extendedPublicKeys.put(keystore.getExtendedPublicKey(), keystore.getKeyDerivation());
////            }
//        }
//        
//        if let _version = version {
//            self.version = _version
//        }
//        
//        var inputIndex = 0
//        for utxoEntry in walletTransaction.utxoSelectors.enumerated() {
////            let walletNode = utxoEntry.element.value
////            let signingWallet = walletNode.wallet
//            
////            let alwaysIncludeWitnessUtxo = signingWallet.keystores.contains { $0.walletModel.alwaysIncludeNonWitnessUtxo }
//            
//            guard let utxo = signingWallet.transactions[utxoEntry.element.key.hash]?.transaction else { continue }
//            let utxoIndex = Int(utxoEntry.element.key.index)
//            guard let utxoOutput = utxo.outputs[utxoIndex] else { continue }
//            
//            guard let txInput = walletTransaction.transaction.inputs[inputIndex] else { continue }
//            
//            var redeemScript: Script? = nil
//            if utxoOutput.script.isScriptType(.P2SH) {
//                redeemScript = txInput.scriptSig.firstNestedScript
//            }
//            
//            var witnessScript: Script? = nil
//            if let witness = txInput.witness {
//                witnessScript = witness.witnessScript
//            }
//            
//            var derivedPublicKeys = [ECKey: KeyDerivation]()
//            var tapInternalKey: ECKey? = nil
//            for keystore in signingWallet.keystores {
//                derivedPublicKeys[signingWallet.scriptType.outputKey(keystore.pubKey(walletNode))] = keystore.keyDerivation.extend(walletNode.derivation)
//                
//                //TODO: Implement Musig for multisig wallets
//                if signingWallet.scriptType == .P2TR {
//                    tapInternalKey = keystore.pubKey(walletNode)
//                }
//            }
//            
//            let psbtInput = PSBTInput(self, signingWallet.scriptType, transaction, inputIndex, utxo, utxoIndex, redeemScript, witnessScript, derivedPublicKeys, [:], tapInternalKey, alwaysIncludeWitnessUtxo)
//            psbtInputs.append(psbtInput)
//            
//            inputIndex += 1
//        }
//    }
    
    public init(psbt: [UInt8]) throws {
        self.psbtBytes = psbt
        try parse(verifySignatures: true)
    }
    
    public init(psbt: [UInt8], verifySignatures: Bool) throws {
        self.psbtBytes = psbt
        try parse(verifySignatures: verifySignatures)
    }
    
    private func parse(verifySignatures: Bool) throws {
        var seenInputs = 0
        var seenOutputs = 0
        
        var psbtByteBuffer = ByteBuffer(bytes: psbtBytes!)
        
        guard let magicBuf = psbtByteBuffer.readBytes(length: 4), PSBT.PSBT_MAGIC_HEX == magicBuf.toHexString() else {
            throw PSBTError.message("PSBT has invalid magic value")
        }
        
        guard let sep = psbtByteBuffer.readBytes(length: 1) else {
            throw PSBTError.message("PSBT has invalid sep value")
        }
        if sep.first != 0xff {
            throw PSBTError.message("PSBT has bad initial separator: " + sep.toHexString())
        }
        
        var currentState = PSBT.STATE_GLOBALS
        var globalEntries = [PSBTEntry]()
        var inputEntryLists = [[PSBTEntry]]()
        var outputEntryLists = [[PSBTEntry]]()
        
        var inputEntries = [PSBTEntry]()
        var outputEntries = [PSBTEntry]()
        while psbtByteBuffer.readableBytes > 0 {
            let entry = try PSBTEntry(psbtByteBuffer: &psbtByteBuffer)
            
            if entry.key == nil {         // length == 0
                switch currentState {
                case PSBT.STATE_GLOBALS:
                    currentState = PSBT.STATE_INPUTS
                    try parseGlobalEntries(globalEntries: globalEntries)
                case PSBT.STATE_INPUTS:
                    inputEntryLists.append(inputEntries)
                    inputEntries = [PSBTEntry]()
                    
                    seenInputs += 1
                    if seenInputs == inputs {
                        currentState = PSBT.STATE_OUTPUTS
                        try parseInputEntries(inputEntryLists: inputEntryLists, verifySignatures: verifySignatures)
                    }
                case PSBT.STATE_OUTPUTS:
                    outputEntryLists.append(outputEntries)
                    outputEntries = [PSBTEntry]()
                    
                    seenOutputs += 1
                    if seenOutputs == outputs {
                        currentState = PSBT.STATE_END
                        try parseOutputEntries(outputEntryLists: outputEntryLists)
                    }
                case PSBT.STATE_END:
                    break
                default:
                    throw PSBTError.message("PSBT structure invalid")
                }
            } else if currentState == PSBT.STATE_GLOBALS {
                globalEntries.append(entry)
            } else if currentState == PSBT.STATE_INPUTS {
                inputEntries.append(entry)
            } else if currentState == PSBT.STATE_OUTPUTS {
                outputEntries.append(entry)
            } else {
                throw PSBTError.message("PSBT structure invalid")
            }
        }
        
        if currentState != PSBT.STATE_END {
            if transaction == nil {
                throw PSBTError.message("Missing transaction")
            }
        }
    }
    
    private func parseGlobalEntries(globalEntries: [PSBTEntry]) throws {
        guard findDuplicateKey(entries: globalEntries) == nil else {
            throw PSBTError.message("Found duplicate key for PSBT global")
        }

        for entry in globalEntries {
            switch entry.keyType {
            case PSBT.PSBT_GLOBAL_UNSIGNED_TX:
                try entry.checkOneByteKey()
                let transaction = Transaction(rawtx: entry.data!)
                try transaction.verify()
                inputs = transaction.inputs.count
                outputs = transaction.outputs.count
                for input in transaction.inputs {
                    if try input.getScriptSig().getProgram().count != 0 {
                        throw PSBTError.message("Unsigned tx input does not have empty scriptSig")
                    }
                }
                self.transaction = transaction
            case PSBT.PSBT_GLOBAL_BIP32_PUBKEY:
                try entry.checkOneBytePlusXpubKey()
                let keyDerivation = try PSBTEntry.parseKeyDerivation(data: Data(entry.data!))
                let pubKey = try ExtendedKey.fromDescriptor(descriptor: entry.keyData!.base58CheckEncodedString)
                self.extendedPublicKeys[pubKey] = keyDerivation
            case PSBT.PSBT_GLOBAL_VERSION:
                try entry.checkOneByteKey()
                let version = Int(Utils.readUint32(bytes: entry.data ?? [UInt8](), offset: 0))
                self.version = version
            case PSBT.PSBT_GLOBAL_PROPRIETARY:
                globalProprietary[entry.keyData?.toHexString() ?? ""] = entry.keyData?.toHexString() ?? ""
            default:
                break
            }
        }
    }
    
    private func parseInputEntries(inputEntryLists: [[PSBTEntry]], verifySignatures: Bool) throws {
        for inputEntries in inputEntryLists {
            if let duplicate = findDuplicateKey(entries: inputEntries) {
                throw PSBTError.message("Found duplicate key for PSBT input: \(duplicate.key?.toHexString() ?? "")")
            }

            let inputIndex = self.psbtInputs.count
            let input = try PSBTInput(psbt: self, inputEntries: inputEntries, transaction: transaction!, index: inputIndex)
            self.psbtInputs.append(input)
        }

        if verifySignatures {
            try verifysignatures(psbtInputs: psbtInputs)
        }
    }

    private func parseOutputEntries(outputEntryLists: [[PSBTEntry]]) throws {
        for outputEntries in outputEntryLists {
            if let duplicate = findDuplicateKey(entries: outputEntries) {
                throw PSBTError.message("Found duplicate key for PSBT output: \(duplicate.key?.toHexString() ?? "")")
            }

            let output = try PSBTOutput(outputEntries: outputEntries)
            self.psbtOutputs.append(output)
        }
    }

    private func findDuplicateKey(entries: [PSBTEntry]) -> PSBTEntry? {
        var checkSet = Set<String>()
        for entry in entries {
            if !checkSet.insert(entry.key!.toHexString()).inserted {
                return entry
            }
        }

        return nil
    }
    
    public func getFee() -> Int64? {
        var fee: Int64 = 0

        for input in psbtInputs {
            guard let utxo = input.getUtxo() else {
                return nil
            }
            fee += utxo.value
        }

        for output in transaction!.outputs {
            fee -= output.value
        }

        return fee
    }

    public func verifySignatures() throws {
        try verifysignatures(psbtInputs: psbtInputs)
    }
    
    
    private func verifysignatures(psbtInputs: [PSBTInput]) throws {
        for input in psbtInputs {
            let verified = try input.verifySignatures()
            if !verified && !input.partialSignatures.isEmpty {
                throw PSBTError.message("Unverifiable partial signatures provided")
            }
            if !verified && input.isTaproot() && input.tapKeyPathSignature != nil {
                throw PSBTError.message("Unverifiable taproot keypath signature provided")
            }
        }
    }
    public func hasSignatures() -> Bool {
        for psbtInput in psbtInputs {
            if !psbtInput.partialSignatures.isEmpty || psbtInput.tapKeyPathSignature != nil || psbtInput.finalScriptSig != nil || psbtInput.finalScriptWitness != nil {
                return true
            }
        }

        return false
    }
    
    public func isSigned() -> Bool {
        for psbtInput in psbtInputs {
            if !psbtInput.isSigned() {
                return false
            }
        }
        return true
    }

    public func isFinalized() -> Bool {
        for psbtInput in psbtInputs {
            if !psbtInput.isFinalized() {
                return false
            }
        }
        return true
    }
    
    private func getGlobalEntries() throws -> [PSBTEntry] {
        var entries: [PSBTEntry] = []

        if let transaction = transaction {
            entries.append(PSBTEntry.populateEntry(type: PSBT.PSBT_GLOBAL_UNSIGNED_TX, keyData: nil, data: try transaction.bitcoinSerialize(useWitnessFormat: false)))
        }

        for (key, value) in extendedPublicKeys {
            entries.append(PSBTEntry.populateEntry(type: PSBT.PSBT_GLOBAL_BIP32_PUBKEY, keyData: key.getExtendedKeyBytes(), data: try PSBTEntry.serializeKeyDerivation(keyDerivation: value).bytes))
        }

        if let version = version {
            var versionBytes = [UInt8](repeating: 0, count: 4)
            Utils.uint32ToByteArrayLE(val: Int64(version), out: &versionBytes, offset: 0)
            entries.append(PSBTEntry.populateEntry(type: PSBT.PSBT_GLOBAL_VERSION, keyData: nil, data: versionBytes))
        }

        for (key, value) in globalProprietary {
            entries.append(PSBTEntry.populateEntry(type: PSBT.PSBT_GLOBAL_PROPRIETARY, keyData: Data(hex: key).bytes, data: Data(hex: value).bytes))
        }

        return entries
    }

    public func serialize(includeXpubs: Bool = true, includeNonWitnessUtxos: Bool = true) throws -> [UInt8] {
        var baos: [UInt8] = []

        baos.append(contentsOf: Data(hex: PSBT.PSBT_MAGIC_HEX).bytes)
        baos.append(0xff)

        let globalEntries = try getGlobalEntries()
        for entry in globalEntries {
            if includeXpubs || (entry.keyType != PSBT.PSBT_GLOBAL_BIP32_PUBKEY && entry.keyType != PSBT.PSBT_GLOBAL_PROPRIETARY) {
                entry.serializeToStream(&baos)
            }
        }
        baos.append(0x00)

        for psbtInput in psbtInputs {
            let inputEntries = try psbtInput.getInputEntries()
            for entry in inputEntries {
                if (includeXpubs || (entry.keyType != PSBTInput.PSBT_IN_BIP32_DERIVATION && entry.keyType != PSBTInput.PSBT_IN_PROPRIETARY
                                     && entry.keyType != PSBTInput.PSBT_IN_TAP_INTERNAL_KEY && entry.keyType != PSBTInput.PSBT_IN_TAP_BIP32_DERIVATION))
                    && (includeNonWitnessUtxos || entry.keyType != PSBTInput.PSBT_IN_NON_WITNESS_UTXO) {
                    entry.serializeToStream(&baos)
                }
            }
            baos.append(0x00)
        }

        for psbtOutput in psbtOutputs {
            let outputEntries = try psbtOutput.getOutputEntries()
            for entry in outputEntries {
                if includeXpubs || (entry.keyType != PSBTOutput.PSBT_OUT_REDEEM_SCRIPT && entry.keyType != PSBTOutput.PSBT_OUT_WITNESS_SCRIPT
                                    && entry.keyType != PSBTOutput.PSBT_OUT_BIP32_DERIVATION && entry.keyType != PSBTOutput.PSBT_OUT_PROPRIETARY
                                    && entry.keyType != PSBTOutput.PSBT_OUT_TAP_INTERNAL_KEY && entry.keyType != PSBTOutput.PSBT_OUT_TAP_BIP32_DERIVATION) {
                    entry.serializeToStream(&baos)
                }
            }
            baos.append(0x00)
        }

        return baos
    }
    
    public func combine(psbts: [PSBT]) throws {
        for psbt in psbts {
            try combine(psbt: psbt)
        }
    }

    public func combine(psbt: PSBT) throws {
        guard let txBytes = try? transaction?.bitcoinSerialize(), let psbtTxBytes = try? psbt.transaction?.bitcoinSerialize() else {
            throw PSBTError.message("PSBT transaction error")
        }

        if txBytes != psbtTxBytes {
            throw PSBTError.message("Provided PSBT does contain a matching global transaction")
        }

        if isFinalized() || psbt.isFinalized() {
            throw PSBTError.message("Cannot combine an already finalised PSBT")
        }

        if let psbtVersion = psbt.version {
            version = psbtVersion
        }

        extendedPublicKeys.merge(psbt.extendedPublicKeys) { (_, new) in new }
        globalProprietary.merge(psbt.globalProprietary) { (_, new) in new }

        for i in 0..<psbtInputs.count {
            let thisInput = psbtInputs[i]
            let otherInput = psbt.psbtInputs[i]
            thisInput.combine(psbtInput: otherInput)
        }

        for i in 0..<psbtOutputs.count {
            let thisOutput = psbtOutputs[i]
            let otherOutput = psbt.psbtOutputs[i]
            thisOutput.combine(psbtOutput: otherOutput)
        }
    }
    
    public func extractTransaction() throws -> Transaction {
        var hasWitness = false
        for psbtInput in psbtInputs {
            if psbtInput.finalScriptWitness != nil {
                hasWitness = true
            }
        }

        let finalTransaction = Transaction(rawtx: try transaction!.bitcoinSerialize())

        if hasWitness && !finalTransaction.isSegwit() {
            finalTransaction.setSegwitFlag(segwitFlag: Transaction.DEFAULT_SEGWIT_FLAG)
        }

        for i in 0..<finalTransaction.inputs.count {
            let txInput = finalTransaction.inputs[i]
            let psbtInput = psbtInputs[i]
            txInput.setScriptBytes(scriptBytes: (psbtInput.finalScriptSig == nil ? [] : try psbtInput.finalScriptSig!.getProgram()))

            if hasWitness {
                if let _finalScriptWitness = psbtInput.finalScriptWitness {
                    txInput.witness = _finalScriptWitness
                } else {
                    txInput.witness = TransactionWitness(transaction: finalTransaction)
                }
            }
        }

        return finalTransaction
    }

    public func getPublicCopy() throws -> PSBT {
        do {
            let publicCopy = try PSBT(psbt: serialize())
            publicCopy.extendedPublicKeys.removeAll()
            publicCopy.globalProprietary.removeAll()
            for psbtInput in publicCopy.psbtInputs {
                psbtInput.derivedPublicKeys.removeAll()
                psbtInput.proprietary.removeAll()
            }
            for psbtOutput in publicCopy.psbtOutputs {
                psbtOutput.derivedPublicKeys.removeAll()
                psbtOutput.proprietary.removeAll()
            }

            return publicCopy
        } catch let error {
            throw error
        }
    }
    
    public func moveInput(fromIndex: Int, toIndex: Int) throws {
        try moveItem(list: &psbtInputs, fromIndex: fromIndex, toIndex: toIndex)
        transaction!.moveInput(fromIndex: fromIndex, toIndex: toIndex)
        for i in 0..<psbtInputs.count {
            psbtInputs[i].index = i
        }
    }

    public func moveOutput(fromIndex: Int, toIndex: Int) throws {
        try moveItem(list: &psbtOutputs, fromIndex: fromIndex, toIndex: toIndex)
        transaction!.moveOutput(fromIndex: fromIndex, toIndex: toIndex)
    }

    private func moveItem<T>(list: inout [T], fromIndex: Int, toIndex: Int) throws {
        if fromIndex < 0 || fromIndex >= list.count || toIndex < 0 || toIndex >= list.count {
            throw PSBTError.message("Invalid indices [\(fromIndex), \(toIndex)] provided to list of size \(list.count)")
        }

        let item = list.remove(at: fromIndex)
        list.insert(item, at: toIndex)
    }
    
    public func getKeyDerivation(publicKey: ExtendedKey) -> KeyDerivation? {
        return extendedPublicKeys[publicKey]
    }
    
    public func toString() throws -> String {
        return try serialize().toHexString()
    }

    public func toBase64String() throws -> String {
        return try toBase64String(includeXpubs: true)
    }

    public func toBase64String(includeXpubs: Bool) throws -> String {
        return Data(try serialize(includeXpubs: includeXpubs, includeNonWitnessUtxos: true)).base64EncodedString()
    }
    
    public static func isPSBT(b: [UInt8]) throws -> Bool {
        let buffer = Data(b)
        let header = buffer.withUnsafeBytes { $0.load(as: Int.self) }
        return header == PSBT_MAGIC_INT
    }

    public static func isPSBT(s: String) -> Bool {
        if Utils.isHex(s: s) && s.hasPrefix(PSBT_MAGIC_HEX) {
            return true
        } else {
            return Utils.isBase64(s: s) && Data(base64Encoded: s)!.toHexString().hasPrefix(PSBT_MAGIC_HEX)
        }
    }

    public static func fromString(strPSBT: String) throws -> PSBT {
        return try fromString(strPSBT: strPSBT, verifySignatures: true)
    }

    public static func fromString(strPSBT: String, verifySignatures: Bool) throws -> PSBT {
        var _strPSBT = strPSBT
        if !isPSBT(s: _strPSBT) {
            throw PSBTError.message("Provided string is not a PSBT")
        }

        if Utils.isBase64(s: _strPSBT) && !Utils.isHex(s: _strPSBT) {
            _strPSBT = Data(base64Encoded: strPSBT)!.toHexString()
        }
        
        let psbtBytes = Data(hex: _strPSBT).bytes
        return try PSBT(psbt: psbtBytes, verifySignatures: verifySignatures)
    }
}

public enum PSBTError: Error, LocalizedError {
    case unknow
    case message(String)
    
    public var errorDescription: String? {
        switch self {
        case .message(let error):
            return "\(error)"
        default:
            return "unknow error"
        }
    }
}
