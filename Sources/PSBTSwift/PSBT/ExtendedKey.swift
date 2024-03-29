//
//  ExtendedKey.swift
//
//
//  Created by 薛跃杰 on 2024/2/22.
//

import Foundation
import Base58Swift
import BIP32Swift
import NIOCore

public class ExtendedKey: Hashable {
    
    public let parentFingerprint: Data
    public let key: DeterministicKey
    public let keyChildNumber: ChildNumber
    public let hierarchy: DeterministicHierarchy
    
    public init(key: DeterministicKey, parentFingerprint: Data, keyChildNumber: ChildNumber) {
        self.parentFingerprint = parentFingerprint
        self.key = key
        self.keyChildNumber = keyChildNumber
        self.hierarchy = DeterministicHierarchy(rootKey: key)
    }
    
    public func getKey(path: [ChildNumber]) throws -> DeterministicKey {
        return try hierarchy.get(path: path)
    }
    
    public func toString() -> String {
        return getExtendedKey()
    }
    
    public func toString(extendedKeyHeader: Header) -> String {
        return getExtendedKey(extendedKeyHeader: extendedKeyHeader)
    }
    
    public func getExtendedKey() -> String {
        return getExtendedKeyBytes().base58CheckEncodedString
    }
    
    public func getExtendedKey(extendedKeyHeader: Header) -> String {
        return  getExtendedKeyBytes(extendedKeyHeader: extendedKeyHeader).base58CheckEncodedString
    }
    
    public func getExtendedKeyBytes() -> [UInt8] {
        return getExtendedKeyBytes(extendedKeyHeader: key.isPublicKeyOnly() ? Network.get().xpubHeader : Network.get().xprvHeader)
    }
    
    public func getExtendedKeyBytes(extendedKeyHeader: Header) -> [UInt8] {
        var buffer = [UInt8](repeating: 0, count: 78)
        buffer.append(contentsOf: withUnsafeBytes(of: extendedKeyHeader.header.bigEndian, Array.init))
        buffer.append(UInt8(key.depth))
        buffer.append(contentsOf: parentFingerprint)
        buffer.append(contentsOf: withUnsafeBytes(of: keyChildNumber.i.bigEndian, Array.init))
        buffer.append(contentsOf: key.chainCode)
        if key.isPublicKeyOnly() {
            buffer.append(contentsOf: key.getPublickey())
        } else {
            buffer.append(0)
            buffer.append(contentsOf: key.node?.privateKey ?? Data())
        }

        return buffer
    }
    
    public static func fromDescriptor(descriptor: String) throws -> ExtendedKey {
        guard let decodedata = descriptor.base58CheckDecodedData else {
            throw PSBTError.message("ExtendedKey descriptor base58CheckDecod error")
        }
        var buffer = ByteBuffer(bytes: decodedata.bytes)
        guard let headerInt = buffer.readInteger(as: Int32.self) else {
            throw PSBTError.message("ExtendedKey readInt error")
        }
        let header = try Header.getHeader(headerInt: Int(headerInt))
        if header == nil {
            throw PSBTError.unknow
        }

        guard let depthBytes = buffer.readBytes(length: 1), let depthByte = depthBytes.first else {
            throw PSBTError.message("ExtendedKey get depth error")
        }
        let depth = Int(depthByte) & 0xFF
        guard let parentFingerprint = buffer.readBytes(length: 4) else {
            throw PSBTError.message("ExtendedKey get parentFingerprint error")
        }
        guard let t = buffer.readInteger(as: Int32.self) else {
            throw PSBTError.message("ExtendedKey get i error")
        }
        let i = Int(t)
        var childNumber: ChildNumber
        let path: [ChildNumber]

        if depth == 0 && !header!.isPrivateKey {
            childNumber = try ChildNumber(childNumber: 0, isHardened: false)
        } else if (i & ChildNumber.HARDENED_BIT) != 0 {
            childNumber = try ChildNumber(childNumber: i ^ ChildNumber.HARDENED_BIT, isHardened: true)
        } else {
            childNumber = try ChildNumber(childNumber: i, isHardened: false)
        }
        path = [childNumber]

        guard let chainCode =  buffer.readBytes(length: 32), let data = buffer.readBytes(length: 33) else {
            throw PSBTError.message("ExtendedKey readBytes error")
        }
        if buffer.readableBytes > 0 {
            throw PSBTError.message("Found unexpected data in key")
        }

        if header!.isPrivateKey {
            let prvKey = DeterministicKey(parent: nil, priv: Data(data[1..<33]), childNumberPath: path, chainCode: chainCode)
            return ExtendedKey(key: prvKey, parentFingerprint: Data(parentFingerprint), keyChildNumber: childNumber)
        } else {
            let pubKey = DeterministicKey(parent: nil, publicKey: Data(data), childNumberPath: path, depth: Int(depth), parentFingerprint: parentFingerprint, chainCode: chainCode)
            return ExtendedKey(key: pubKey, parentFingerprint: Data(parentFingerprint), keyChildNumber: childNumber)
        }
    }
    
    public static func == (lhs: ExtendedKey, rhs: ExtendedKey) -> Bool {
        return lhs.toString() == rhs.toString()
    }
    
    public var hashValue: Int {
        return toString().hashValue
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(parentFingerprint)
    }
}

public enum Header: String, CaseIterable {
    case xprv = "xprv"
    case xpub = "xpub"
    case yprv = "yprv"
    case ypub = "ypub"
    case zprv = "zprv"
    case zpub = "zpub"
    case Yprv = "Yprv"
    case Ypub = "Ypub"
    case Zprv = "Zprv"
    case Zpub = "Zpub"
    case tprv = "tprv"
    case tpub = "tpub"
    case uprv = "uprv"
    case upub = "upub"
    case vprv = "vprv"
    case vpub = "vpub"
    case Uprv = "Uprv"
    case Upub = "Upub"
    case Vprv = "Vprv"
    case Vpub = "Vpub"

    public var name: String {
        return self.rawValue
    }

    public var header: Int {
        switch self {
        case .xprv: return 0x0488ADE4
        case .xpub: return 0x0488B21E
        case .yprv: return 0x049D7878
        case .ypub: return 0x049D7CB2
        case .zprv: return 0x04b2430c
        case .zpub: return 0x04B24746
        case .Yprv: return 0x0295b005
        case .Ypub: return 0x0295b43f
        case .Zprv: return 0x02aa7a99
        case .Zpub: return 0x02aa7ed3
        case .tprv: return 0x04358394
        case .tpub: return 0x043587cf
        case .uprv: return 0x044a4e28
        case .upub: return 0x044a5262
        case .vprv: return 0x045f18bc
        case .vpub: return 0x045f1cf6
        case .Uprv: return 0x024285b5
        case .Upub: return 0x024289ef
        case .Vprv: return 0x02575048
        case .Vpub: return 0x02575483
        }
    }

    public var defaultScriptType: ScriptType {
        switch self {
        case .xprv, .xpub, .tprv, .tpub:
            return .P2PKH
        case .yprv, .ypub, .uprv, .upub:
            return .P2SH_P2WPKH
        case .zprv, .zpub, .vprv, .vpub:
            return .P2WPKH
        case .Yprv, .Ypub, .Uprv, .Upub:
            return .P2SH_P2WSH
        case .Zprv, .Zpub, .Vprv, .Vpub:
            return .P2WSH
        }
    }

    public var isPrivateKey: Bool {
        switch self {
        case .xprv, .yprv, .zprv, .Yprv, .Zprv, .tprv, .uprv, .vprv, .Uprv, .Vprv:
            return true
        case .xpub, .ypub, .zpub, .Ypub, .Zpub, .tpub, .upub, .vpub, .Upub, .Vpub:
            return false
        }
    }

    public var isMainnet: Bool {
        switch self {
        case .xprv, .xpub, .yprv, .ypub, .zprv, .zpub, .Yprv, .Ypub, .Zprv, .Zpub:
            return true
        case .tprv, .tpub, .uprv, .upub, .vprv, .vpub, .Uprv, .Upub, .Vprv, .Vpub:
            return false
        }
    }
    
    public func getNetwork() -> Network {
        return isMainnet ? Network.mainnet : Network.testnet
    }
    
    public static func getHeaders(network: Network) -> [Header] {
        return Header.allCases.filter { header in
            header.getNetwork() == network || (header.getNetwork() == Network.testnet && network == Network.regtest) || (header.getNetwork() == Network.testnet && network == Network.signet)
        }
    }

    public static func fromExtendedKey(xkey: String) throws -> Header {
        for extendedKeyHeader in getHeaders(network: Network.get()) {
            if xkey.hasPrefix(extendedKeyHeader.name) {
                return extendedKeyHeader
            }
        }

        for network in getOtherNetworks(providedNetwork: Network.get()) {
            for otherNetworkKeyHeader in getHeaders(network: network) {
                if xkey.hasPrefix(otherNetworkKeyHeader.name) {
                    throw PSBTError.message("Provided \(otherNetworkKeyHeader.name) extended key invalid on configured \(Network.get().rawValue) network. Use a \(network.rawValue) configuration to use this extended key.")
                }
            }
        }

        throw PSBTError.message("Unrecognised extended key header for \(Network.get().rawValue): \(xkey)")
    }
    
    public static func fromScriptType(scriptType: ScriptType, privateKey: Bool) -> Header? {
        for header in getHeaders(network: Network.get()) {
            if header.defaultScriptType == scriptType && header.isPrivateKey == privateKey {
                return header
            }
        }

        return Network.get().xpubHeader
    }

    public static func getHeader(headerInt: Int) throws -> Header? {
        for extendedKeyHeader in getHeaders(network: Network.get()) {
            if headerInt == extendedKeyHeader.header {
                return extendedKeyHeader
            }
        }

        for otherNetwork in Header.getOtherNetworks(providedNetwork: Network.get()) {
            for otherNetworkKeyHeader in getHeaders(network: otherNetwork) {
                if headerInt == otherNetworkKeyHeader.header {
                    throw PSBTError.message("Provided \(otherNetworkKeyHeader.name) extended key invalid on configured \(Network.get().rawValue) network. Use a \(otherNetwork.rawValue) configuration to use this extended key.")
                }
            }
        }

        return nil
    }

    private static func getOtherNetworks(providedNetwork: Network) -> [Network] {
        return Network.allCases.filter { $0 != providedNetwork }
    }
}
