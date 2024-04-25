//
//  PSBTInput.swift
//  
//
//  Created by 薛跃杰 on 2024/1/25.
//

import Foundation
//import BitcoinSwift

public class PSBTInput {
    public static let PSBT_IN_NON_WITNESS_UTXO: UInt8 = 0x00
    public static let PSBT_IN_WITNESS_UTXO: UInt8 = 0x01
    public static let PSBT_IN_PARTIAL_SIG: UInt8 = 0x02
    public static let PSBT_IN_SIGHASH_TYPE: UInt8 = 0x03
    public static let PSBT_IN_REDEEM_SCRIPT: UInt8 = 0x04
    public static let PSBT_IN_WITNESS_SCRIPT: UInt8 = 0x05
    public static let PSBT_IN_BIP32_DERIVATION: UInt8 = 0x06
    public static let PSBT_IN_FINAL_SCRIPTSIG: UInt8 = 0x07
    public static let PSBT_IN_FINAL_SCRIPTWITNESS: UInt8 = 0x08
    public static let PSBT_IN_POR_COMMITMENT: UInt8 = 0x09
    public static let PSBT_IN_PROPRIETARY: UInt8 = 0xfc
    public static let PSBT_IN_TAP_KEY_SIG: UInt8 = 0x13
    public static let PSBT_IN_TAP_BIP32_DERIVATION: UInt8 = 0x16
    public static let PSBT_IN_TAP_INTERNAL_KEY: UInt8 = 0x17

    public let psbt: PSBT
    public var nonWitnessUtxo: Transaction?
    public var witnessUtxo: TransactionOutput?
    public var partialSignatures = [[UInt8]: TransactionSignature]()
    public var sigHash: SigHash?
    public var redeemScript: Script?
    public var witnessScript: Script?
    public var derivedPublicKeys = [[UInt8]: KeyDerivation]()
    public var finalScriptSig: Script?
    public var finalScriptWitness: TransactionWitness?
    public var porCommitment: String?
    public var proprietary = [String: String]()
    public var tapKeyPathSignature: TransactionSignature?
    public var tapDerivedPublicKeys = [[UInt8]: [KeyDerivation: [Data]]]()
    public var tapInternalKey: [UInt8]?

    public var transaction: Transaction
    public var index: Int = 0
    
    public init(psbt: PSBT, transaction: Transaction, index: Int) {
        self.psbt = psbt
        self.transaction = transaction
        self.index = index
    }
    
    
    public init(psbt: PSBT, 
                nonWitnessUtxo: Transaction? = nil,
                witnessUtxo: TransactionOutput? = nil,
                sigHash: SigHash? = nil,
                redeemScript: Script? = nil,
                witnessScript: Script? = nil,
                finalScriptSig: Script? = nil,
                finalScriptWitness: TransactionWitness? = nil,
                porCommitment: String? = nil,
                proprietary: [String : String] = [String: String](),
                tapKeyPathSignature: TransactionSignature? = nil,
                tapInternalKey: [UInt8]? = nil,
                transaction: Transaction, index: Int) {
        self.psbt = psbt
        self.nonWitnessUtxo = nonWitnessUtxo
        self.witnessUtxo = witnessUtxo
        self.sigHash = sigHash
        self.redeemScript = redeemScript
        self.witnessScript = witnessScript
        self.finalScriptSig = finalScriptSig
        self.finalScriptWitness = finalScriptWitness
        self.porCommitment = porCommitment
        self.proprietary = proprietary
        self.tapKeyPathSignature = tapKeyPathSignature
        self.tapInternalKey = tapInternalKey
        self.transaction = transaction
        self.index = index
    }
    
    public init(psbt: PSBT, inputEntries: [PSBTEntry], transaction: Transaction, index: Int) throws {
        self.psbt = psbt
        self.transaction = transaction
        self.index = index

        for entry in inputEntries {
            switch entry.keyType {
            case PSBTInput.PSBT_IN_NON_WITNESS_UTXO:
                do {
                    try entry.checkOneByteKey()
                    let nonWitnessTx = Transaction(rawtx: entry.data ?? [UInt8]())
                    try nonWitnessTx.verify()
                    let inputHash = try nonWitnessTx.calculateTxId(useWitnesses: false)
                    let outpointHash = transaction.inputs[index].outpoint!.hashData
                    if outpointHash != inputHash {
                        throw PSBTError.message("Hash of provided non witness utxo transaction \(inputHash) does not match transaction input outpoint hash \(outpointHash) at index \(index)")
                    }

                    self.nonWitnessUtxo = nonWitnessTx
                } catch let error {
                    throw error
                }
            case PSBTInput.PSBT_IN_WITNESS_UTXO: 
                do {
                    try entry.checkOneByteKey()
                    let witnessTxOutput = TransactionOutput(parent: nil, rawtx: entry.data ?? [UInt8](), offset: 0)
                    if try !ScriptType.P2SH.isScriptType(script: witnessTxOutput.getScript()) && !ScriptType.P2WPKH.isScriptType(script: witnessTxOutput.getScript()) && !ScriptType.P2WSH.isScriptType(script: witnessTxOutput.getScript()) && !ScriptType.P2TR.isScriptType(script: witnessTxOutput.getScript()) {
                        throw PSBTError.message("Witness UTXO provided for non-witness or unknown input")
                    }

                    self.witnessUtxo = witnessTxOutput
                } catch let error {
                    throw error
                }
            case PSBTInput.PSBT_IN_PARTIAL_SIG:
                do {
                    try entry.checkOneBytePlusPubKey()
                    guard let sigPublicKey = entry.keyData, let entryData = entry.data else {
                        throw PSBTError.message("PSBTInput init PSBT_IN_PARTIAL_SIG entry keyData or entrydata nil")
                    }
                    if (entryData.count == 64 || entryData.count == 65) {
                        throw PSBTError.message("Schnorr signature provided as ECDSA partial signature, ignoring")
                    }
                    self.partialSignatures[sigPublicKey] = try TransactionSignature.decodeFromBitcoin(type: TransactionType.ecdsa, data: entryData, requireCanonicalEncoding: true)
                } catch let error {
                    throw error
                }
            case PSBTInput.PSBT_IN_SIGHASH_TYPE: 
                do {
                    try entry.checkOneByteKey()
                    guard let entryData = entry.data else {
                        throw PSBTError.message("Invalid sighash type")
                    }
                    let sighashType = entryData.withUnsafeBytes { $0.load(as: UInt32.self) }
                    guard let sigHash = SigHash(rawValue: UInt8(sighashType)) else {
                        throw PSBTError.message("Invalid sighash type")
                    }
                    self.sigHash = sigHash
                } catch let error {
                    throw error
                }
            case PSBTInput.PSBT_IN_REDEEM_SCRIPT: 
                do {
                    try entry.checkOneByteKey()
                    guard let entrydata = entry.data, let redeemScript = try? Script(programBytes: entrydata) else {
                        throw PSBTError.message("Invalid entry data")
                    }
                    var scriptPubKey: Script? = nil
                    if self.nonWitnessUtxo != nil {
                        scriptPubKey = try self.nonWitnessUtxo?.outputs[Int(transaction.inputs[index].outpoint!.index)].getScript()
                    } else if self.witnessUtxo != nil {
                        scriptPubKey = try self.witnessUtxo?.getScript()
                        if try !ScriptType.P2WPKH.isScriptType(script: redeemScript) && !ScriptType.P2WSH.isScriptType(script: redeemScript) {
                            throw PSBTError.message("Witness UTXO provided but redeem script is not P2WPKH or P2WSH")
                        }
                    }
                    if scriptPubKey == nil {
                        throw PSBTError.message("PSBT provided a redeem script for a transaction output that was not provided")
                    } else {
                        if try !ScriptType.P2SH.isScriptType(script: scriptPubKey!) {
                            throw PSBTError.message("PSBT provided a redeem script for a transaction output that does not need one")
                        }
                        if let input = try? redeemScript.getProgram(),let hash160 = Utils.sha256hash160(input: input)?.bytes, let pubhash = try? scriptPubKey!.getPubKeyHash(), (hash160 != pubhash) {
                            throw PSBTError.message("Redeem script hash does not match transaction output script pubkey hash \(try scriptPubKey!.getPubKeyHash().toHexString())")
                        }
                    }
                    self.redeemScript = redeemScript
                } catch let error {
                    throw error
                }
            case PSBTInput.PSBT_IN_WITNESS_SCRIPT: 
                do {
                    try entry.checkOneByteKey()
                    var pubKeyHash: [UInt8]? = nil
                    guard let entryData = entry.data, let _witnessScript = try? Script(programBytes: entryData) else {
                        throw PSBTError.message("Invalid entry data")
                    }
                    if let _redeemScript = self.redeemScript, try ScriptType.P2WSH.isScriptType(script: _redeemScript) {
                        try pubKeyHash = _redeemScript.getPubKeyHash()
                    } else if let _witnessUtxo = self.witnessUtxo, try ScriptType.P2WSH.isScriptType(script: _witnessUtxo.getScript()) { //P2WSH
                        pubKeyHash = try self.witnessUtxo!.getScript().getPubKeyHash()
                    }
                    guard pubKeyHash != nil else {
                        throw PSBTError.message("Witness script hash does not match provided pay to script hash \(pubKeyHash!.toHexString())")
                    }
                    let _witnessScriptData = try _witnessScript.getProgram()
                    if _witnessScriptData.sha256() != pubKeyHash {
                        throw PSBTError.message("Witness script hash does not match provided pay to script hash \(pubKeyHash!.toHexString())")
                    }
                    self.witnessScript = _witnessScript
                } catch let error {
                    throw error
                }
            case PSBTInput.PSBT_IN_BIP32_DERIVATION: 
                do {
                    try entry.checkOneBytePlusPubKey()
                    guard let entrydata = entry.data, let entryKeyData = entry.keyData else {
                        throw PSBTError.message("Invalid entry data")
                    }
//                    ECKey derivedPublicKey = ECKey.fromPublicOnly(entry.getKeyData());
                    let keyDerivation = try PSBTEntry.parseKeyDerivation(data: Data(entrydata))
                    self.derivedPublicKeys[entryKeyData] = keyDerivation
                } catch let error {
                    throw error
                }
            case PSBTInput.PSBT_IN_FINAL_SCRIPTSIG: 
                do {
                    try entry.checkOneByteKey()
                    guard let entrydata = entry.data else {
                        throw PSBTError.message("Invalid entry data")
                    }
                    self.finalScriptSig = try Script(programBytes: entrydata)
                } catch let error {
                    throw error
                }
            case PSBTInput.PSBT_IN_FINAL_SCRIPTWITNESS: 
                do {
                    try entry.checkOneByteKey()
                    guard let entrydata = entry.data else {
                        throw PSBTError.message("Invalid entry data")
                    }
                    let finalScriptWitness = TransactionWitness(parent: nil, rawtx: entrydata, offset: 0)
                    self.finalScriptWitness = finalScriptWitness
                } catch let error {
                    throw error
                }
            case PSBTInput.PSBT_IN_POR_COMMITMENT: 
                try entry.checkOneByteKey()
                guard let entrydata = entry.data else {
                    throw PSBTError.message("Invalid entry data")
                }
                let porMessage = String(data: Data(entrydata), encoding: .utf8)
                self.porCommitment = porMessage
            case PSBTInput.PSBT_IN_PROPRIETARY: 
                guard let entrydata = entry.data else {
                    throw PSBTError.message("Invalid entry data")
                }
                self.proprietary[entrydata.toHexString()] = entrydata.toHexString()
            case PSBTInput.PSBT_IN_TAP_KEY_SIG: 
                try entry.checkOneByteKey()
                guard let entrydata = entry.data else {
                    throw PSBTError.message("Invalid entry data")
                }
                self.tapKeyPathSignature = try TransactionSignature.decodeFromBitcoin(type: TransactionType.schnorr, data: entrydata, requireCanonicalEncoding: true)
            case PSBTInput.PSBT_IN_TAP_BIP32_DERIVATION: 
                try entry.checkOneBytePlusXOnlyPubKey()
                guard let tapPublicKey = entry.keyData, let entryData = entry.data else {
                    throw PSBTError.message("Invalid entry key data")
                }
                let tapKeyDerivations = try PSBTEntry.parseTaprootKeyDerivation(data: Data(entryData))
                if(tapKeyDerivations.isEmpty) {
                    throw PSBTError.message("PSBT provided an invalid input taproot key derivation");
                } else {
                    self.tapDerivedPublicKeys[tapPublicKey] = tapKeyDerivations
                }
                break;
            case PSBTInput.PSBT_IN_TAP_INTERNAL_KEY: 
                try entry.checkOneByteKey()
                    guard let tapInternalKey = entry.data else {
                        throw PSBTError.message("Invalid entry data")
                    }
                self.tapInternalKey = tapInternalKey
                break
            default:
                break
            }
        }
        self.transaction = transaction
        self.index = index
    }
    
    public func getInputEntries() throws -> [PSBTEntry] {
        var entries: [PSBTEntry] = []
        
        if let nonWitnessUtxo = nonWitnessUtxo {
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_NON_WITNESS_UTXO, keyData: nil, data: try nonWitnessUtxo.bitcoinSerialize(useWitnessFormat: false)))
        }
        
        if let witnessUtxo = witnessUtxo {
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_WITNESS_UTXO, keyData: nil, data: try witnessUtxo.bitcoinSerialize()))
        }
        
        for entry in partialSignatures {
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_PARTIAL_SIG, keyData: entry.key, data: try entry.value.encodeToBitcoin()))
        }
        
        if let _sigHash = sigHash {
            var sigHashBytes = [UInt8](repeating: 0, count: 4)
            Utils.uint32ToByteArrayLE(val: Int64(_sigHash.rawValue), out: &sigHashBytes, offset: 0)
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_SIGHASH_TYPE, keyData: nil, data: sigHashBytes))
        }
        
        if let redeemScript = redeemScript {
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_REDEEM_SCRIPT, keyData: nil, data: try redeemScript.getProgram()))
        }
        
        if let witnessScript = witnessScript {
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_WITNESS_SCRIPT, keyData: nil, data: try witnessScript.getProgram()))
        }
        
        for entry in derivedPublicKeys {
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_BIP32_DERIVATION, keyData: entry.key, data: try PSBTEntry.serializeKeyDerivation(keyDerivation: entry.value).bytes))
        }
        
        if let finalScriptSig = finalScriptSig {
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_FINAL_SCRIPTSIG, keyData: nil, data: try finalScriptSig.getProgram()))
        }
        
        if let finalScriptWitness = finalScriptWitness {
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_FINAL_SCRIPTWITNESS, keyData: nil, data: try finalScriptWitness.toByteArray().bytes))
        }
        
        if let porCommitment = porCommitment {
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_POR_COMMITMENT, keyData: nil, data: porCommitment.data(using: .utf8)!.bytes))
        }
        
        for entry in proprietary {
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_PROPRIETARY, keyData: Data(hex: entry.key).bytes, data: Data(hex: entry.value).bytes))
        }
        
        if let tapKeyPathSignature = tapKeyPathSignature {
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_TAP_KEY_SIG, keyData: nil, data: try tapKeyPathSignature.encodeToBitcoin()))
        }
        
        for entry in tapDerivedPublicKeys {
            if !entry.value.isEmpty {
                entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_TAP_BIP32_DERIVATION, keyData: entry.key, data: try PSBTEntry.serializeTaprootKeyDerivation(leafHashes: [Data](), keyDerivation: entry.value.keys.first!).bytes))
            }
        }
        
        if let tapInternalKey = tapInternalKey {
            entries.append(PSBTEntry.populateEntry(type: PSBTInput.PSBT_IN_TAP_INTERNAL_KEY, keyData: nil, data: tapInternalKey))
        }
        
        return entries
    }
    
    public func combine(psbtInput: PSBTInput) {
        if let nonWitnessUtxo = psbtInput.nonWitnessUtxo {
            self.nonWitnessUtxo = nonWitnessUtxo
        }

        if let witnessUtxo = psbtInput.witnessUtxo {
            self.witnessUtxo = witnessUtxo
        }

        self.partialSignatures.merge(psbtInput.partialSignatures) { (_, new) in new }

        if let sigHash = psbtInput.sigHash {
            self.sigHash = sigHash
        }

        if let redeemScript = psbtInput.redeemScript {
            self.redeemScript = redeemScript
        }

        if let witnessScript = psbtInput.witnessScript {
            self.witnessScript = witnessScript
        }

        self.derivedPublicKeys.merge(psbtInput.derivedPublicKeys) { (_, new) in new }

        if let porCommitment = psbtInput.porCommitment {
            self.porCommitment = porCommitment
        }

        self.proprietary.merge(psbtInput.proprietary) { (_, new) in new }

        if let tapKeyPathSignature = psbtInput.tapKeyPathSignature {
            self.tapKeyPathSignature = tapKeyPathSignature
        }

        self.tapDerivedPublicKeys.merge(psbtInput.tapDerivedPublicKeys) { (_, new) in new }

        if let tapInternalKey = psbtInput.tapInternalKey {
            self.tapInternalKey = tapInternalKey
        }
    }
    
    public func getPartialSignature(publicKey: [UInt8]) -> TransactionSignature? {
        return partialSignatures[publicKey]
    }
    
    public func getKeyDerivation(publicKey: [UInt8]) -> KeyDerivation? {
        return derivedPublicKeys[publicKey]
    }
    
    public func getKeyForSignature(signature: TransactionSignature) -> [UInt8]? {
        for entry in partialSignatures {
            if entry.value == signature {
                return entry.key
            }
        }
        return nil
    }
    
    public func isTaproot() -> Bool {
        guard let _ = getUtxo(), let scriptType = try? getScriptType(), scriptType == ScriptType.P2TR else {
            return false
        }
        return true
    }
    
    public func isSigned() -> Bool {
        if self.tapKeyPathSignature != nil {
            return true
        } else if self.partialSignatures.isEmpty {
            do {
                //All partial sigs are already verified
                let reqSigs = try getSigningScript()!.getNumRequiredSignatures()
                let sigs = self.partialSignatures.count
                return sigs >= reqSigs
            } catch {
                return false
            }
        } else {
            return isFinalized()
        }
    }
    
    public func sign(privateKey: Data, publicKey: Data) throws -> Bool {
        var localSigHash = sigHash
        if localSigHash == nil {
            localSigHash = getDefaultSigHash()
        }
        
        if nonWitnessUtxo != nil || witnessUtxo != nil {
            let signingScript = try getSigningScript()
            if signingScript != nil {
                let hash = try getHashForSignature(connectedScript: signingScript!, localSigHash: localSigHash!)
                let type = isTaproot() ? SignatureType.SCHNORR : SignatureType.ECDSA
                
                let transactionSignature = try TransactionSignature.sign(privateKey: privateKey, publicKey: publicKey, input: hash, sigHash: localSigHash!, type: type)
                
                if type == .SCHNORR {
                    tapKeyPathSignature = transactionSignature
                } else {
                    partialSignatures[publicKey.bytes] = transactionSignature
                }
                
                return true
            }
        }
        
        return false
    }
    
    func verifySignatures() throws -> Bool {
        var localSigHash: SigHash
        if let _localSigHash = sigHash {
            localSigHash = _localSigHash
        } else {
            localSigHash = getDefaultSigHash()
        }

        if nonWitnessUtxo != nil || witnessUtxo != nil {
            guard let signingScript = try getSigningScript() else {
                return false
            }
            let hash = try getHashForSignature(connectedScript: signingScript, localSigHash: localSigHash)

            if isTaproot() && tapKeyPathSignature != nil {
                guard let outputKey = try? ScriptType.P2TR.getPublicKeyFromScript(script: try getUtxo()!.getScript()) else {
                    throw PSBTError.message("Tweaked internal key does not verify against provided taproot keypath signature")
                }
                if !(try tapKeyPathSignature?.verify(hash: hash, pub: outputKey))! {
                    throw PSBTError.message("Tweaked internal key does not verify against provided taproot keypath signature")
                }
            } else {
                for sigPublicKey in partialSignatures.keys {
                    let signature = getPartialSignature(publicKey: sigPublicKey)
                    if !(try signature?.verify(hash: hash, pub: Data(sigPublicKey)))! {
                        throw PSBTError.message("Partial signature does not verify against provided public key")
                    }
                }
            }

            return true
        }

        return false
    }
    
    public func getSignatures() throws -> [TransactionSignature] {
        if let finalScriptWitness = finalScriptWitness {
            return try finalScriptWitness.getSignatures()
        } else if let finalScriptSig = finalScriptSig {
            return try finalScriptSig.getSignatures()
        } else if let tapKeyPathSignature = tapKeyPathSignature {
            return [tapKeyPathSignature]
        } else {
            return Array(partialSignatures.values)
        }
    }

    private func getDefaultSigHash() -> SigHash {
        if isTaproot() {
            return SigHash.DEFAULTType
        }

        return SigHash.ALL
    }
    
    public func getSigningKeys(availableKeys: [Data]) throws -> [Data: TransactionSignature] {
        let signatures = try getSignatures()
        let signingScript = try getSigningScript()

        var signingKeys = [Data: TransactionSignature]()
        if let _signingScript = signingScript {
            let hash = try getHashForSignature(connectedScript: _signingScript, localSigHash:  sigHash ?? getDefaultSigHash())

            for sigPublicKey in availableKeys {
                for signature in signatures {
                    if try signature.verify(hash: hash, pub: sigPublicKey) {
                        signingKeys[sigPublicKey] = signature
                    }
                }
            }
        }

        return signingKeys
    }

    public func getScriptType() throws -> ScriptType? {
        guard var signingScript = try? getUtxo()?.getScript() else {
            return nil
        }
        var p2sh = false
        if try ScriptType.P2SH.isScriptType(script: signingScript) {
            p2sh = true
            if let redeemScript = redeemScript {
                signingScript = redeemScript
            } else if let finalScriptSig = finalScriptSig, let _signingScript = try? finalScriptSig.getFirstNestedScript() {
                signingScript = _signingScript
            } else {
                return nil
            }
        }
        if try ScriptType.P2WPKH.isScriptType(script: signingScript) {
            return p2sh ? .P2SH_P2WPKH : .P2WPKH
        } else if try ScriptType.P2WSH.isScriptType(script: signingScript) {
            return p2sh ? .P2SH_P2WSH : .P2WSH
        }
        return try ScriptType.getType(script: signingScript)
    }
    
    public func getSigningScript() throws -> Script? {
        guard var signingScript = try? getUtxo()?.getScript() else {
            return nil
        }

        if try ScriptType.P2SH.isScriptType(script: signingScript) {
            if let redeemScript = redeemScript {
                signingScript = redeemScript
            } else if let finalScriptSig = finalScriptSig, let signingScript = try? finalScriptSig.getFirstNestedScript() {
                return signingScript
            } else {
                return nil
            }
        }

        if try ScriptType.P2WPKH.isScriptType(script: signingScript) {
            signingScript = try ScriptType.P2PKH.getOutputScript(pubKey: try signingScript.getPubKeyHash())
        } else if try ScriptType.P2WSH.isScriptType(script: signingScript) {
            if let witnessScript = witnessScript {
                signingScript = witnessScript
            } else if let finalScriptWitness = finalScriptWitness, let witnessScript = try? finalScriptWitness.getWitnessScript() {
                return witnessScript
            } else {
                return nil
            }
        }

        if try ScriptType.P2TR.isScriptType(script: signingScript) {
            // For now, only support keypath spends and just return the ScriptPubKey
            // In future return the script from PSBT_IN_TAP_LEAF_SCRIPT
        }
        return signingScript
    }
    
    public func isFinalized() -> Bool {
        if let _ = finalScriptSig, let _ = finalScriptWitness {
            return true
        } else {
            return false
        }
    }

    public func getUtxo() -> TransactionOutput? {
        let vout = transaction.inputs[index].outpoint!.index
        if let _witnessUtxo = witnessUtxo {
            return _witnessUtxo
        } else if let _nonWitnessUtxo = nonWitnessUtxo {
            return _nonWitnessUtxo.outputs[Int(vout)]
        } else {
            return nil
        }
    }
    
    public func clearNonFinalFields() {
         partialSignatures.removeAll()
         sigHash = nil
         redeemScript = nil
         witnessScript = nil
         porCommitment = nil
         proprietary.removeAll()
         tapDerivedPublicKeys.removeAll()
         tapKeyPathSignature = nil
     }
    
    private func getHashForSignature(connectedScript: Script, localSigHash: SigHash) throws -> Data {
        var hash: Data

        let scriptType = try getScriptType()
        if scriptType == ScriptType.P2TR {
            let spentUtxos = psbt.psbtInputs.map { $0.getUtxo() }
            hash = try transaction.hashForTaprootSignature(spentUtxos: spentUtxos, inputIndex: index, scriptPath: try !ScriptType.P2TR.isScriptType(script: connectedScript), script: connectedScript, sigHash: localSigHash, annex: nil)
        } else if let _scriptType = scriptType, ScriptType.WITNESS_TYPES.contains(_scriptType) {
            let prevValue = getUtxo()?.value ?? 0
            hash = try transaction.hashForWitnessSignature(inputIndex: index, scriptCode: connectedScript, prevValue: prevValue, sigHash: localSigHash)
        } else {
            hash = try transaction.hashForLegacySignature(inputIndex: index, redeemScript: connectedScript, sigHash: localSigHash)
        }

        return hash
    }
}
