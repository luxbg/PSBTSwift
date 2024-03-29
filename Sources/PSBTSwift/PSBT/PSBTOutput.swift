//
//  PSBTOutput.swift
//
//
//  Created by 薛跃杰 on 2024/1/25.
//

import Foundation
import BIP32Swift

public class PSBTOutput {
    public static let PSBT_OUT_REDEEM_SCRIPT: UInt8 = 0x00
    public static let PSBT_OUT_WITNESS_SCRIPT: UInt8 = 0x01
    public static let PSBT_OUT_BIP32_DERIVATION: UInt8 = 0x02
    public static let PSBT_OUT_TAP_INTERNAL_KEY: UInt8 = 0x05
    public static let PSBT_OUT_TAP_BIP32_DERIVATION: UInt8 = 0x07
    public static let PSBT_OUT_PROPRIETARY: UInt8 = 0xfc
    public var redeemScript: Script?
    public var witnessScript: Script?
    public var derivedPublicKeys = [[UInt8]: KeyDerivation]()
    public var proprietary = [String: String]()
    public var tapDerivedPublicKeys = [[UInt8]: [KeyDerivation: [Data]]]()
    public var publicKey: [UInt8]?
    
    public init() {
        self.redeemScript = nil
        self.witnessScript = nil
        self.publicKey = nil
    }

    public init(scriptType: ScriptType, redeemScript: Script, witnessScript: Script, derivedPublicKeys: [[UInt8]: KeyDerivation], proprietary: [String: String], publicKey: [UInt8]?) {
        self.redeemScript = redeemScript
        self.witnessScript = witnessScript

        if scriptType != .P2TR {
            self.derivedPublicKeys = derivedPublicKeys
        }

        self.proprietary = proprietary

        self.publicKey = publicKey
//        tapInternalKey?.getPubKeyXCoord()

        if let tapInternalKey = publicKey, !derivedPublicKeys.values.isEmpty {
            let tapKeyDerivation = derivedPublicKeys.values.first!
            tapDerivedPublicKeys[self.publicKey!] = [tapKeyDerivation: []]
        }
    }
    
    public init(outputEntries: [PSBTEntry]) throws {
        for entry in outputEntries {
            switch entry.keyType {
            case PSBTOutput.PSBT_OUT_REDEEM_SCRIPT:
                try entry.checkOneByteKey()
                let redeemScript = try Script(programBytes: entry.data!)
                self.redeemScript = redeemScript
            case PSBTOutput.PSBT_OUT_WITNESS_SCRIPT:
                try entry.checkOneByteKey()
                let witnessScript = try Script(programBytes: entry.data!)
                self.witnessScript = witnessScript
            case PSBTOutput.PSBT_OUT_BIP32_DERIVATION:
                try entry.checkOneBytePlusPubKey()
                let derivedPublicKey = entry.data
                //                    ECKey(publicOnly: entry.keyData)
                let keyDerivation = try PSBTEntry.parseKeyDerivation(data: Data(entry.data!))
                self.derivedPublicKeys[derivedPublicKey!] = keyDerivation
            case PSBTOutput.PSBT_OUT_PROPRIETARY:
                proprietary[entry.keyData!.toHexString()] = entry.data!.toHexString()
            case PSBTOutput.PSBT_OUT_TAP_INTERNAL_KEY:
                try entry.checkOneByteKey()
                self.publicKey = entry.data
                //                    ECKey(publicOnly: entry.data)
            case PSBTOutput.PSBT_OUT_TAP_BIP32_DERIVATION:
                try entry.checkOneBytePlusXOnlyPubKey()
                let tapPublicKey = entry.keyData
                //                    ECKey(publicOnly: entry.keyData)
                let tapKeyDerivations = try PSBTEntry.parseTaprootKeyDerivation(data: Data(entry.data!))
                if tapPublicKey!.isEmpty {
                } else {
                    self.tapDerivedPublicKeys[tapPublicKey!] = tapKeyDerivations
                }
            default:
                throw PSBTError.message("PSBT output not recognized key type: \(entry.keyType)")
            }
        }
    }
    
    public func getOutputEntries() throws -> [PSBTEntry] {
        var entries = [PSBTEntry]()

        if let redeemScript = self.redeemScript {
            entries.append(PSBTEntry.populateEntry(type: PSBTOutput.PSBT_OUT_REDEEM_SCRIPT, keyData: nil, data: redeemScript.program))
        }

        if let witnessScript = self.witnessScript {
            entries.append(PSBTEntry.populateEntry(type: PSBTOutput.PSBT_OUT_WITNESS_SCRIPT, keyData: nil, data: witnessScript.program))
        }

        for (key, value) in self.derivedPublicKeys {
            entries.append(PSBTEntry.populateEntry(type: PSBTOutput.PSBT_OUT_BIP32_DERIVATION, keyData: key, data: try? PSBTEntry.serializeKeyDerivation(keyDerivation: value).bytes))
        }

        for (key, value) in self.proprietary {
            entries.append(PSBTEntry.populateEntry(type: PSBTOutput.PSBT_OUT_PROPRIETARY, keyData: Data(hex: key).bytes, data:Data(hex: value).bytes))
        }

        for (key, value) in self.tapDerivedPublicKeys {
            if !value.isEmpty {
//                entries.append(PSBTEntry.populateEntry(type: PSBTOutput.PSBT_OUT_TAP_BIP32_DERIVATION, keyData: key.pubKeyXCoord, data: serializeTaprootKeyDerivation([], value.keys.first!)))
            }
        }

//        if let tapInternalKey = self.tapInternalKey {
//            entries.append(PSBTEntry.populateEntry(type: PSBTOutput.PSBT_OUT_TAP_INTERNAL_KEY, keyData: nil, data: tapInternalKey.pubKeyXCoord))
//        }
        if let publicKey = self.publicKey {
            entries.append(PSBTEntry.populateEntry(type: PSBTOutput.PSBT_OUT_TAP_INTERNAL_KEY, keyData: nil, data: publicKey))
        }
        return entries
    }
    
    public func combine(psbtOutput: PSBTOutput) {
        if let redeemScript = psbtOutput.redeemScript {
            self.redeemScript = redeemScript
        }

        if let witnessScript = psbtOutput.witnessScript {
            self.witnessScript = witnessScript
        }

        self.derivedPublicKeys.merge(psbtOutput.derivedPublicKeys) { (_, new) in new }
        self.proprietary.merge(psbtOutput.proprietary) { (_, new) in new }
        self.tapDerivedPublicKeys.merge(psbtOutput.tapDerivedPublicKeys) { (_, new) in new }

//        if let tapInternalKey = psbtOutput.tapInternalKey {
//            self.tapInternalKey = tapInternalKey
//        }
        if let publicKey = psbtOutput.publicKey {
            self.publicKey = publicKey
        }
    }
    
    public func clearNonFinalFields() {
        self.tapDerivedPublicKeys.removeAll()
    }
}
