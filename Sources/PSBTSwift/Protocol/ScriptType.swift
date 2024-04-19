//
//  ScriptType.swift
//
//
//  Created by 薛跃杰 on 2024/1/16.
//

import Foundation
import CryptoSwift
//import BitcoinSwift

public enum ScriptType: String, CaseIterable {
    
    public static let SINGLE_KEY_TYPES: [ScriptType] = [.P2PK, .P2TR]

    public static let SINGLE_HASH_TYPES: [ScriptType] = [.P2PKH, .P2SH, .P2SH_P2WPKH, .P2SH_P2WSH, .P2WPKH, .P2WSH]

    public static let ADDRESSABLE_TYPES: [ScriptType] = [.P2PKH, .P2SH, .P2SH_P2WPKH, .P2SH_P2WSH, .P2WPKH, .P2WSH, .P2TR]

    public static let NON_WITNESS_TYPES: [ScriptType] = [.P2PK, .P2PKH, .P2SH]

    public static let WITNESS_TYPES: [ScriptType] = [.P2SH_P2WPKH, .P2SH_P2WSH, .P2WPKH, .P2WSH, .P2TR]
    
    case P2PK, P2PKH, MULTISIG, P2SH, P2SH_P2WPKH, P2SH_P2WSH, P2WPKH, P2WSH, P2TR
    
    public func getWeakedOutputKey(publicKey: Data) -> Data? {
        guard let payload = Utils.getDataXCoord(publicKey) else{
            return nil
        }
        return payload
    }
    
    public func getAddress(pubKey: [UInt8]) throws -> Address {
        switch self {
        case .P2PK: return P2PKAddress(pubKey)
        case .P2PKH: return P2PKHAddress(pubKey)
        case .MULTISIG:
            throw PSBTError.message("No single address for multisig script type")
        case .P2SH: return P2SHAddress(pubKey)
        case .P2SH_P2WPKH: return P2SHAddress(pubKey)
        case .P2SH_P2WSH: return P2SHAddress(pubKey)
        case .P2WPKH: return P2WPKHAddress(pubKey)
        case .P2WSH: return P2WSHAddress(pubKey)
        case .P2TR: return P2TRAddress(pubKey)
        }
    }
    
    public func getAddress(publicKey: Data) throws -> Address {
        switch self {
        case .P2PK: return try getAddress(pubKey: publicKey.bytes)
        case .P2PKH: return try getAddress(pubKey: publicKey.hash160()!.bytes)
        case .MULTISIG:
            throw PSBTError.message("No single key address for wrapped witness script hash type")
        case .P2SH:
            throw PSBTError.message("No single key address for script hash type")
        case .P2SH_P2WPKH:
            let p2wpkhScript = try ScriptType.P2WPKH.getOutputScript(pubKey: publicKey.hash160()!.bytes)
            return try ScriptType.P2SH.getAddress(script: p2wpkhScript)
        case .P2SH_P2WSH:
            throw PSBTError.message("No single key address for wrapped witness script hash type")
        case .P2WPKH:
            return try getAddress(pubKey: publicKey.hash160()!.bytes)
        case .P2WSH:
            throw PSBTError.message("No single key address for witness script hash type")
        case .P2TR:
            guard let data = getWeakedOutputKey(publicKey: publicKey) else {
                throw PSBTError.message("p2tr data error")
            }
            return try getAddress(pubKey: data.bytes)
        }
    }
    
    public func getAddress(script: Script) throws -> Address {
        switch self {
        case .P2PK, .P2PKH: throw PSBTError.message("No script derived address for non pay to script type")
        case .MULTISIG:
            throw PSBTError.message("No single address for multisig script type")
        case .P2SH:
            guard let scriptData = try? script.getProgram(), let hash = Utils.sha256hash160(input: scriptData) else {
                throw PSBTError.message("P2SH script error")
            }
            return try getAddress(pubKey: hash.bytes)
        case .P2SH_P2WPKH:
            if try ScriptType.P2WPKH.isScriptType(script: script) {
                return try ScriptType.P2SH.getAddress(script: script)
            }
            throw PSBTError.message("Provided script is not a P2WPKH script")
        case .P2SH_P2WSH:
            let p2wshScript = try ScriptType.P2WSH.getOutputScript(script: script)
            return try ScriptType.P2SH.getAddress(script: p2wshScript)
        case .P2WPKH:
            throw PSBTError.message("No script derived address for non pay to script type")
        case .P2WSH:
            let hash = try script.getProgram().sha256() 
            return try getAddress(pubKey: hash)
        case .P2TR:
            throw PSBTError.message("Cannot create a taproot address without a keypath")
        }
    }
    
    public func getOutputScript(pubKey: [UInt8]) throws -> Script {
        switch self {
        case .P2PK:
            var chunks = [ScriptChunk]()
            chunks.append(ScriptChunk(opcode: pubKey.count, data: pubKey))
            chunks.append(ScriptChunk(opcode: ScriptOpCodes.OP_CHECKSIG, data: nil))
            return Script(chunks: chunks)
        case .P2PKH:
            var chunks = [ScriptChunk]()
            chunks.append(ScriptChunk(opcode: ScriptOpCodes.OP_DUP, data: nil))
            chunks.append(ScriptChunk(opcode: ScriptOpCodes.OP_HASH160, data: nil))
            chunks.append(ScriptChunk(opcode: pubKey.count, data: pubKey))
            chunks.append(ScriptChunk(opcode: ScriptOpCodes.OP_EQUALVERIFY, data: nil))
            chunks.append(ScriptChunk(opcode: ScriptOpCodes.OP_CHECKSIG, data: nil))
            return Script(chunks: chunks)
        case .MULTISIG:
            throw PSBTError.message("Output script for multisig script type must be constructed with method getOutputScript(int threshold, List<ECKey> pubKeys)")
        case .P2SH:
            var chunks = [ScriptChunk]()
            chunks.append(ScriptChunk(opcode: ScriptOpCodes.OP_HASH160, data: nil))
            chunks.append(ScriptChunk(opcode: pubKey.count, data: pubKey))
            chunks.append(ScriptChunk(opcode: ScriptOpCodes.OP_EQUAL, data: nil))
            return Script(chunks: chunks)
        case .P2SH_P2WPKH:
            return try ScriptType.P2SH.getOutputScript(pubKey: pubKey)
        case .P2SH_P2WSH:
            return try ScriptType.P2SH.getOutputScript(pubKey: pubKey)
        case .P2WPKH, .P2WSH:
            var chunks = [ScriptChunk]()
            chunks.append(ScriptChunk(opcode: ScriptOpCodes.OP_0, data: nil))
            chunks.append(ScriptChunk(opcode: pubKey.count, data: pubKey))
            return Script(chunks: chunks)
        case .P2TR:
            var chunks = [ScriptChunk]()
            chunks.append(ScriptChunk(opcode: ScriptOpCodes.OP_1, data: nil))
            chunks.append(ScriptChunk(opcode: pubKey.count, data: pubKey))
            return Script(chunks: chunks)
        }
    }
    
    public func getOutputScript(publicKey:Data) throws -> Script {
        switch self {
        case .P2PK: return try getOutputScript(pubKey: publicKey.bytes)
        case .P2PKH: return try getOutputScript(pubKey: publicKey.hash160()!.bytes)
        case .MULTISIG:
            throw PSBTError.message("Output script for multisig script type must be constructed with method getOutputScript(int threshold, List<ECKey> pubKeys)")
        case .P2SH:
            throw PSBTError.message("No single key output script for script hash type")
        case .P2SH_P2WPKH:
            return try ScriptType.P2WPKH.getOutputScript(pubKey:publicKey.hash160()!.bytes)
        case .P2SH_P2WSH:
            throw PSBTError.message("No single key output script for wrapped witness script hash type")
        case .P2WPKH:
            return try getOutputScript(pubKey: publicKey.hash160()!.bytes)
        case .P2WSH:
            throw PSBTError.message("No single key output script for witness script hash type")
        case .P2TR:
            guard let data = getWeakedOutputKey(publicKey: publicKey) else {
                throw PSBTError.message("p2tr key error")
            }
            return try getOutputScript(pubKey: data.bytes)
        }
    }
    
    public func getOutputScript(script: Script) throws -> Script {
        switch self {
        case .P2PK: throw PSBTError.message("No script derived output script for non pay to script type")
        case .P2PKH: throw PSBTError.message("No script derived output script for non pay to script type")
        case .MULTISIG:
            if try isScriptType(script: script) {
                return script
            }
            throw PSBTError.message("No script derived output script for non pay to script type")
        case .P2SH:
            guard let program = try? script.getProgram(), let data = Utils.sha256hash160(input: program) else {
                throw PSBTError.message("P2SH script error")
            }
            return try getOutputScript(pubKey: data.bytes)
        case .P2SH_P2WPKH:
            if try ScriptType.P2WPKH.isScriptType(script: script) {
                return try ScriptType.P2SH.getOutputScript(script: script)
            }
        case .P2SH_P2WSH:
            throw PSBTError.message("Provided script is not a P2WPKH script")
        case .P2WPKH:
            throw PSBTError.message("No script derived output script for non pay to script type")
        case .P2WSH:
            return try getOutputScript(pubKey: script.getProgram().sha256())
        case .P2TR:
            throw PSBTError.message("Cannot create a taproot output script without a keypath")
        }
        return try Script(programBytes: [UInt8]())
    }
    
    public func getOutputScript(threshold: Int, pubKeys: [Data]) throws -> Script {
        switch self {
        case .MULTISIG:
            guard threshold <= pubKeys.count else {
                throw PSBTError.message("Threshold of \(threshold) is greater than number of pubKeys provided (\(pubKeys.count))")
            }

            var pubKeyBytes: [[UInt8]] = []
            for key in pubKeys {
                pubKeyBytes.append(key.bytes)
            }
            pubKeyBytes.sort { $0.lexicographicallyPrecedes($1) }

            var chunks: [ScriptChunk] = []
            chunks.append(ScriptChunk(opcode: try Script.encodeToOpN(threshold), data: nil))
            for pubKey in pubKeyBytes {
                chunks.append(ScriptChunk(opcode: pubKey.count, data: pubKey))
            }
            chunks.append(ScriptChunk(opcode: try Script.encodeToOpN(pubKeys.count), data: nil))
            chunks.append(ScriptChunk(opcode: ScriptOpCodes.OP_CHECKMULTISIG, data: nil))
            return Script(chunks: chunks)
        default:
            throw PSBTError.message("Only defined for MULTISIG script type")
        }
    }
    
    public func getOutputDescriptor(publicKey: Data) throws -> String {
        switch self {
        case .P2PK, .P2PKH, .P2SH_P2WPKH, .P2WPKH, .P2TR: return getDescriptor() + publicKey.toHexString() + getCloseDescriptor()
        case .MULTISIG:
            throw PSBTError.message("No single key output descriptor for multisig script type")
        case .P2SH, .P2SH_P2WSH, .P2WSH:
            throw PSBTError.message("No single key output descriptor for script hash type")
        }
    }
    
    public func getOutputDescriptor(script: Script) throws -> String {
        switch self {
        case .P2PK: 
            throw PSBTError.message("No script derived output descriptor for non pay to script type")
        case .P2PKH, .P2SH, .P2SH_P2WPKH, .P2WPKH:
            throw PSBTError.message("No script derived output descriptor for non pay to script type")
        case .MULTISIG:
            if try !isScriptType(script: script) {
                throw PSBTError.message("Can only create output descriptor from multisig script")
            }
            let threshold = try getThreshold(script: script)
            let pubKeys = try getPublicKeysFromScript(script: script)

            var pubKeyBytes = [Data]()
            for pubKey in pubKeys {
                pubKeyBytes.append(pubKey)
            }
            pubKeyBytes.sort { $0.lexicographicallyPrecedes($1) }

            var joiner = [String]()
            for pubKey in pubKeyBytes {
                joiner.append(pubKey.toHexString())
            }
            return getDescriptor() + String(threshold) + "," + joiner.joined(separator: ",") + getCloseDescriptor()
        case .P2SH_P2WSH, .P2WSH:
            guard try ScriptType.MULTISIG.isScriptType(script: script) else {
                throw PSBTError.message("Can only create output descriptor from multisig script")
            }
            let descriptor = try ScriptType.MULTISIG.getOutputDescriptor(script: script)
            return getDescriptor() + descriptor + getCloseDescriptor()
        case .P2TR:
            throw PSBTError.message("Cannot create a taproot output descriptor without a keypath")
        }
    }
    
    public func getDescriptor() -> String {
        switch self {
        case .P2PK: return "pk("
        case .P2PKH: return "pkh("
        case .MULTISIG: return "sortedmulti("
        case .P2SH: return "sh("
        case .P2SH_P2WPKH: return "sh(wpkh("
        case .P2SH_P2WSH:return "sh(wsh("
        case .P2WPKH: return "wpkh("
        case .P2WSH: return "wsh("
        case .P2TR: return "tr("
        }
    }
    
    public func isScriptType(script: Script) throws -> Bool {
        switch self {
        case .P2PK:
            let chunks = script.chunks
            if chunks.count != 2 { return false }
            if !chunks[0].equalsOpCode(0x21) && !chunks[0].equalsOpCode(0x41) { return false }
            guard let chunk2data = chunks[0].data else { return false }
            if chunk2data.count != 33 && chunk2data.count != 65 { return false }
            if !chunks[1].equalsOpCode(ScriptOpCodes.OP_CHECKSIG) { return false }
            return true
        case .P2PKH:
            let chunks = script.chunks
            if chunks.count != 5 { return false }
            if !chunks[0].equalsOpCode(ScriptOpCodes.OP_DUP) { return false }
            if !chunks[1].equalsOpCode(ScriptOpCodes.OP_HASH160) { return false }
            guard let chunk2data = chunks[2].data else { return false }
            if chunk2data.count != 20 { return false }
            if !chunks[3].equalsOpCode(ScriptOpCodes.OP_EQUALVERIFY) { return false }
            if !chunks[4].equalsOpCode(ScriptOpCodes.OP_CHECKSIG) { return false }
            return true
        case .MULTISIG:
            let chunks = script.chunks
            if chunks.count < 4 { return false }
            guard let chunk = chunks.last else { return false }
            if !chunk.isOpCode() { return false }
            if !(chunk.equalsOpCode(ScriptOpCodes.OP_CHECKMULTISIG) || chunk.equalsOpCode(ScriptOpCodes.OP_CHECKMULTISIGVERIFY)) { return false }
            let m = chunks[chunks.count - 2]
            if !m.isOpCode() { return false }
            let numKeys = try Script.decodeFromOpN(m.opcode)
            if numKeys < 1 || chunks.count != 3 + numKeys { return false }
            for i in 1..<chunks.count - 2 {
                if chunks[i].isOpCode() { return false }
            }
            if try Script.decodeFromOpN(chunks[0].opcode) < 1 { return false }
            return true
        case .P2SH:
            let chunks = script.chunks
            if chunks.count != 3 { return false }
            if !chunks[0].equalsOpCode(ScriptOpCodes.OP_HASH160) { return false }
            let chunk1 = chunks[1]
            if chunk1.opcode != 0x14 { return false }
            guard let chunk1data = chunk1.data else { return false }
            if chunk1data.count != 20 { return false }
            if !chunks[2].equalsOpCode(ScriptOpCodes.OP_EQUAL) { return false }
            return true
        case .P2SH_P2WPKH:
            return try ScriptType.P2SH.isScriptType(script: script)
        case .P2SH_P2WSH:
            return try ScriptType.P2SH.isScriptType(script: script)
        case .P2WPKH:
            let chunks = script.chunks
            if chunks.count != 2 { return false }
            if !chunks[0].equalsOpCode(ScriptOpCodes.OP_0) { return false }
            guard let chunk1data = chunks[1].data else { return false }
            if chunk1data.count != 20 { return false }
            return true
        case .P2WSH:
            let chunks = script.chunks
            if chunks.count != 2 { return false }
            if !chunks[0].equalsOpCode(ScriptOpCodes.OP_0) { return false }
            guard let chunk1data = chunks[1].data else { return false }
            if chunk1data.count != 32 { return false }
            return true
        case .P2TR:
            let chunks = script.chunks
            if chunks.count != 2 { return false }
            if !chunks[0].equalsOpCode(ScriptOpCodes.OP_1) { return false }
            guard let chunk1data = chunks[1].data else { return false }
            if chunk1data.count != 32 { return false }
            return true
        }
    }
    
    public func getHashFromScript(script: Script) throws -> [UInt8] {
        switch self {
        case .P2PK:
            throw PSBTError.message("P2PK script does contain hash, use getPublicKeyFromScript(script) to retreive public key")
        case .P2PKH: 
            guard let data = script.chunks[2].data else {
                throw PSBTError.message("P2PKH script error")
            }
            return data
        case .MULTISIG:
            throw PSBTError.message("Public keys for bare multisig script type must be retrieved with method getPublicKeysFromScript(Script script)")
        case .P2SH: 
            guard let data = script.chunks[1].data else {
                throw PSBTError.message("P2SH script error")
            }
            return data
        case .P2SH_P2WPKH: return try ScriptType.P2SH.getHashFromScript(script: script)
        case .P2SH_P2WSH: return try ScriptType.P2SH.getHashFromScript(script: script)
        case .P2WPKH: 
            guard let data = script.chunks[1].data else {
                throw PSBTError.message("P2WPKH script error")
            }
            return data
        case .P2WSH: 
            guard let data = script.chunks[1].data else {
                throw PSBTError.message("P2WSH script error")
            }
            return data
        case .P2TR:
            throw PSBTError.message("P2TR script does not contain a hash, use getPublicKeyFromScript(script) to retrieve public key")
        }
    }
    
    public func getPublicKeysFromScript(script: Script) throws -> [Data] {
        switch self {
        case .MULTISIG:
            var pubKeys = [Data]()
            let chunks = script.chunks
            for i in 1..<chunks.count - 2 {
                if let pubKey = chunks[i].data {
                    pubKeys.append(Data(pubKey))
                } else {
                    pubKeys.append(Data())
                }
            }
            return pubKeys
        default:
            throw PSBTError.message("Script type \(self) does not contain public keys")
        }
    }
    
    public func getThreshold(script: Script) throws -> Int {
        switch self {
        case .MULTISIG:
            return try Script.decodeFromOpN(script.chunks[0].opcode)
        case .P2TR:
            throw PSBTError.message("Script type \(self)  is not a multisig script")
        default:
            throw PSBTError.message("Not support getThreshold")
        }
        
    }
    
    public func getPublicKeyFromScript(script: Script) throws -> Data {
        switch self {
        case .P2PK:
            guard let publicKeydata = script.chunks[0].data else {
                throw PSBTError.message("public key error")
            }
            return Data(publicKeydata)
        case .P2TR:
            guard let publicKeydata = script.chunks[1].data else {
                throw PSBTError.message("public key error")
            }
            return Data(publicKeydata)
        default:
            throw PSBTError.message("Script type \(self) does not contain a public key")
        }
    }
    
    public func getScriptSig(scriptPubKey: Script, pubKey: Data, signature: Data) throws -> Script {
        switch self {
        case .P2PK:
            if try !isScriptType(script: scriptPubKey) {
                throw PSBTError.message("Provided scriptPubKey is not a \(self) script")
            }
            
            let signatureBytes = signature.bytes
            let signatureChunk = try ScriptChunk.fromData(data: signatureBytes)
            return Script(chunks: [signatureChunk])
        case .P2PKH:
            if try !isScriptType(script: scriptPubKey) {
                throw PSBTError.message("Provided scriptPubKey is not a \(self) script")
            }
            
            let signatureBytes = signature.bytes
            let signatureChunk = try ScriptChunk.fromData(data: signatureBytes)
            let pubKeyBytes = pubKey.bytes
            let pubKeyChunk = try ScriptChunk.fromData(data: pubKeyBytes)
            return Script(chunks: [signatureChunk, pubKeyChunk])
        case .MULTISIG:
            throw PSBTError.message("\(self) is a multisig script type")
        case .P2SH:
            throw PSBTError.message("Only multisig scriptSigs supported for \(self) scriptPubKeys")
        case .P2SH_P2WPKH:
            guard try isScriptType(script: scriptPubKey) else {
                throw PSBTError.message("Provided scriptPubKey is not a \(self) script")
            }
            
            let redeemScript = try ScriptType.P2WPKH.getOutputScript(pubKey: pubKey.bytes)
            guard try scriptPubKey.isEqual(try ScriptType.P2SH.getOutputScript(script: redeemScript)) else {
                throw PSBTError.message("\(self) scriptPubKey hash does not match constructed redeem script hash")
            }
            let redeemScriptChunk = try ScriptChunk.fromData(data: redeemScript.getProgram())
            return Script(chunks: [redeemScriptChunk])
        case .P2SH_P2WSH:
            throw PSBTError.message("Only multisig scriptSigs supported for \(self) scriptPubKeys")
        case .P2WPKH:
            guard try isScriptType(script: scriptPubKey) else {
                throw PSBTError.message("Provided scriptPubKey is not a \(self) script")
            }
            
            guard try scriptPubKey.isEqual(try getOutputScript(pubKey: pubKey.bytes)) else {
                throw PSBTError.message("P2WPKH scriptPubKey hash does not match constructed pubkey script hash")
            }
            return try Script(programBytes: [UInt8]())
        case .P2WSH:
            throw PSBTError.message("Only multisig scriptSigs supported for \(self) scriptPubKeys")
        case .P2TR:
            guard try isScriptType(script: scriptPubKey) else {
                throw PSBTError.message("Provided scriptPubKey is not a \(self) script")
            }

            let signatureBytes = signature.bytes
            let signatureChunk = try ScriptChunk.fromData(data: signatureBytes)
            return Script(chunks: [signatureChunk])
        }
    }
    
    public func addSpendingInput(transaction: Transaction, prevOutput: TransactionOutput, publicKey: Data, signature: Data) throws -> TransactionInput {
        switch self {
        case .P2PK, .P2PKH:
            let scriptSig = try getScriptSig(scriptPubKey: prevOutput.getScript(), pubKey: publicKey, signature: signature)
            return try transaction.addInput(spendTxHash: try prevOutput.getHash(), outputIndex: prevOutput.getIndex(), script: scriptSig)
        case .MULTISIG:
            throw PSBTError.message("\(self) is a multisig script type")
        case .P2SH:
            throw PSBTError.message("Only multisig scriptSigs supported for \(self) scriptPubKeys")
        case .P2SH_P2WPKH:
            let scriptSig = try getScriptSig(scriptPubKey: prevOutput.getScript(), pubKey:  publicKey, signature: signature)
            let witness = TransactionWitness(transaction: transaction, pubKey: publicKey, signature: signature)
            return try transaction.addInput(spendTxHash: prevOutput.getHash(), outputIndex: prevOutput.getIndex(), script: scriptSig, witness: witness)
        case .P2SH_P2WSH:
            throw PSBTError.message("Only multisig scriptSigs supported for \(self) scriptPubKeys")
        case .P2WPKH:
            let scriptSig = try getScriptSig(scriptPubKey: prevOutput.getScript(), pubKey: publicKey, signature: signature)
            let witness = TransactionWitness(transaction: transaction, pubKey: publicKey, signature: signature)
            return try transaction.addInput(spendTxHash: try prevOutput.getHash(), outputIndex: prevOutput.getIndex(), script: scriptSig, witness: witness)
        case .P2WSH:
            throw PSBTError.message("Only multisig scriptSigs supported for \(self) scriptPubKeys")
        case .P2TR:
            let scriptSig = try getScriptSig(scriptPubKey: prevOutput.getScript(), pubKey: publicKey, signature: signature)
            let witness = TransactionWitness(transaction: transaction, pubKey: publicKey, signature: signature)
            return try transaction.addInput(spendTxHash: try prevOutput.getHash(), outputIndex: prevOutput.getIndex(), script: scriptSig, witness: witness)
        }
    }
    
    public func getMultisigScriptSig(scriptPubKey: Script, threshold: Int, pubKeySignatures: [Data: Data]) throws -> Script {
        switch self {
        case .P2PK, .P2PKH, .P2SH_P2WPKH:
            throw PSBTError.message("\(self) is not a multisig script type")
        case .MULTISIG:
            guard try isScriptType(script: scriptPubKey) else {
                throw PSBTError.message("Provided scriptPubKey is not a \(self) script")
            }

            let signatures = pubKeySignatures.values.compactMap { $0 }
            guard signatures.count >= threshold else {
                throw PSBTError.message("Only \(signatures.count) signatures provided to meet a multisig threshold of \(threshold)")
            }

            var chunks = [ScriptChunk]()
            let opZero = ScriptChunk.fromOpcode(opcode: ScriptOpCodes.OP_0)
            chunks.append(opZero)
            for signature in signatures {
                let signatureBytes = signature.bytes
                chunks.append(try ScriptChunk.fromData(data: signatureBytes))
            }
            return Script(chunks: chunks)
        case .P2SH:
            guard try isScriptType(script: scriptPubKey) else {
                throw PSBTError.message("Provided scriptPubKey is not a \(self) script")
            }

            let redeemScript = try ScriptType.MULTISIG.getOutputScript(threshold: threshold, pubKeys: Array(pubKeySignatures.keys))
            guard try scriptPubKey.isEqual(try getOutputScript(script: redeemScript))  else {
                throw PSBTError.message("P2SH scriptPubKey hash does not match constructed redeem script hash")
            }

            let multisigScript = try ScriptType.MULTISIG.getMultisigScriptSig(scriptPubKey: redeemScript, threshold: threshold, pubKeySignatures: pubKeySignatures)
            var chunks = multisigScript.getChunks()
            let redeemScriptChunk = try ScriptChunk.fromData(data: try redeemScript.getProgram())
            chunks.append(redeemScriptChunk)
            return Script(chunks: chunks)
        case .P2SH_P2WSH:
            guard try isScriptType(script: scriptPubKey) else {
                throw PSBTError.message("Provided scriptPubKey is not a \(self) script")
            }

            let witnessScript = try ScriptType.MULTISIG.getOutputScript(threshold: threshold, pubKeys: Array(pubKeySignatures.keys))
            let redeemScript = try ScriptType.P2WSH.getOutputScript(script: witnessScript)
            guard try scriptPubKey.isEqual(try ScriptType.P2SH.getOutputScript(script: redeemScript)) else {
                throw PSBTError.message("P2SH scriptPubKey hash does not match constructed redeem script hash")
            }

            let redeemScriptChunk = try ScriptChunk.fromData(data: redeemScript.getProgram())
            return Script(chunks: [redeemScriptChunk])
        case .P2WPKH:
            throw PSBTError.message("\(self) is not a multisig script type")
        case .P2WSH:
            guard try isScriptType(script: scriptPubKey) else {
                throw PSBTError.message("Provided scriptPubKey is not a \(self) script")
            }

            let witnessScript = try ScriptType.MULTISIG.getOutputScript(threshold: threshold, pubKeys: Array(pubKeySignatures.keys))
            guard try scriptPubKey.isEqual(try  ScriptType.P2WSH.getOutputScript(script: witnessScript)) else {
                throw PSBTError.message("P2WSH scriptPubKey hash does not match constructed witness script hash")
            }

            return Script(chunks: [])
        case .P2TR:
            throw PSBTError.message("Constructing Taproot inputs is not yet supported")
        }
    }
    
    public func addMultisigSpendingInput(transaction: Transaction, prevOutput: TransactionOutput, threshold: Int, pubKeySignatures: [Data: Data]) throws -> TransactionInput {
        switch self {
        case .P2PK, .P2PKH, .P2SH_P2WPKH, .P2WPKH:
            throw PSBTError.message("\(self) is not a multisig script type")
        case .MULTISIG:
            let scriptSig = try getMultisigScriptSig(scriptPubKey: prevOutput.getScript(), threshold: threshold, pubKeySignatures: pubKeySignatures)
            return try transaction.addInput(spendTxHash: prevOutput.getHash(), outputIndex: prevOutput.getIndex(), script: scriptSig)
        case .P2SH:
            let scriptSig = try getMultisigScriptSig(scriptPubKey: prevOutput.getScript(), threshold: threshold, pubKeySignatures: pubKeySignatures)
            return try transaction.addInput(spendTxHash: prevOutput.getHash(), outputIndex: prevOutput.getIndex(), script: scriptSig)
        case .P2SH_P2WSH:
            let scriptSig = try getMultisigScriptSig(scriptPubKey: prevOutput.getScript(), threshold: threshold, pubKeySignatures: pubKeySignatures)
            let witnessScript = try ScriptType.MULTISIG.getOutputScript(threshold: threshold, pubKeys: Array(pubKeySignatures.keys))
            let witness = try TransactionWitness(transaction: transaction, signatures: Array(pubKeySignatures.values.compactMap { $0 }), witnessScript: witnessScript)
            return try transaction.addInput(spendTxHash: prevOutput.getHash(), outputIndex: prevOutput.getIndex(), script: scriptSig, witness: witness)
        case .P2WSH:
            let scriptSig = try getMultisigScriptSig(scriptPubKey: prevOutput.getScript(), threshold: threshold, pubKeySignatures: pubKeySignatures)
            let witnessScript = try ScriptType.MULTISIG.getOutputScript(threshold: threshold, pubKeys: Array(pubKeySignatures.keys))
            let witness = try TransactionWitness(transaction: transaction, signatures: pubKeySignatures.values.compactMap { $0 }, witnessScript: witnessScript)
            return try transaction.addInput(spendTxHash: prevOutput.getHash(), outputIndex: prevOutput.getIndex(), script: scriptSig, witness: witness)
        case .P2TR:
            throw PSBTError.message("Constructing Taproot inputs is not yet supported")
        }
    }
    
    public func getSignatureType() -> SignatureType {
        switch self {
        case .P2TR:
            return SignatureType.SCHNORR
        default:
            return SignatureType.ECDSA
        }
    }
    
    public func getAllowedPolicyTypes() -> [PolicyType] {
        switch self {
        case .P2PK,.P2PKH, .P2SH_P2WPKH, .P2WPKH, .P2TR:
            return [.SINGLE]
        case .MULTISIG, .P2SH:
            return [.MULTI]
        case .P2SH_P2WSH, .P2WSH:
            return [.SINGLE, .MULTI]
        }
    }
    
    public func getName() -> String {
        return self.rawValue
    }
    
    public func isAllowed(policyType: PolicyType) -> Bool {
        return getAllowedPolicyTypes().contains(policyType)
    }
    
    public func getAddresses(script: Script) throws -> [Address] {
        return [try getAddress(pubKey: getHashFromScript(script: script))]
    }
    
    public static func getScriptTypesForPolicyType(policyType: PolicyType) -> [ScriptType] {
        let scriptTypes: [ScriptType] = ScriptType.allCases
        return scriptTypes.filter { scriptType in
            scriptType.isAllowed(policyType: policyType)
        }
    }
    
    public static func getAddressableScriptTypes(policyType: PolicyType) -> [ScriptType] {
        return ADDRESSABLE_TYPES.filter { scriptType in
            scriptType.isAllowed(policyType: policyType)
        }
    }
    
    public static func getType(script: Script) throws -> ScriptType? {
        let scriptTypes: [ScriptType] = ScriptType.allCases
        return try scriptTypes.first { scriptType in
            try scriptType.isScriptType(script: script)
        }
    }
    
    
    public func getDustThreshold(output: TransactionOutput, feeRate: Double) throws -> Double {
        return try getFee(output: output, feeRate: feeRate, longTermFeeRate: Transaction.DUST_RELAY_TX_FEE)
    }

    public func getFee(output: TransactionOutput, feeRate: Double, longTermFeeRate: Double) throws -> Double {
        let outputVbytes = output.length
        let inputVbytes = try getInputVbytes()
        return Double(feeRate * Double(outputVbytes) + longTermFeeRate * inputVbytes)
    }
    
    public func getInputVbytes() throws -> Double {
        if self == ScriptType.P2SH_P2WPKH {
            return Double(54 + Double(Double(107.0) / Double(Transaction.WITNESS_SCALE_FACTOR)))
        } else if self == ScriptType.P2SH_P2WSH {
            return Double(76 + Double(Double(107.0) / Double(Transaction.WITNESS_SCALE_FACTOR)))
        } else if self == ScriptType.P2TR {
            // Assume a default keypath spend
            return Double(41 + Double(Double(66.0) / Double(Transaction.WITNESS_SCALE_FACTOR)))
        } else if ScriptType.WITNESS_TYPES.contains(self) {
            // Return length of spending input with 75% discount to script size
            return Double(41 + Double(Double(107.0) / Double(Transaction.WITNESS_SCALE_FACTOR)))
        } else if ScriptType.NON_WITNESS_TYPES.contains(self) {
            // Return length of spending input with no discount
            return Double(148)
        } else {
            throw PSBTError.message("Cannot determine dust threshold for script type \(self)")
        }
    }
    
    public func getCloseDescriptor() -> String {
        return getDescriptor().filter { $0 == "(" }.map { _ in ")" }.joined()
    }
}
