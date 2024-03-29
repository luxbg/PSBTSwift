//
//  Address.swift
//
//
//  Created by 薛跃杰 on 2024/1/25.
//

import Foundation
import Bech32
import Base58Swift

public class Address {
    public let data: [UInt8]
    
    public init(_ data: [UInt8]) {
        self.data = data
    }
    
    public func getScriptType() -> ScriptType? {
        return nil
    }
    
    public func getAddress() -> String {
        return ""
    }
    
    public func getAddress(network: Network) -> String {
        return data.encodeChecked(version: getVersion())
    }
    
    public func toString() -> String {
        return toString(network: Network.get())
    }
    
    public func toString(network: Network) -> String {
        return getAddress(network: network)
    }
    
    public func getVersion(network: Network) -> Int {
        return 1
    }
    
    public func getVersion() -> Int {
        return getVersion(network: Network.get())
    }
    
    public func getOutputScript() throws -> Script? {
        throw PSBTError.unknow
    }
    
    public func getOutputScriptData() -> [UInt8] {
        return data
    }
    
    public func equals(obj: Any) -> Bool {
        guard let address = obj as? Address else {
            return false
        }
        
        return data == address.data && getVersion(network: Network.get()) == address.getVersion(network: Network.get())
    }
    
    public func hashCode() -> Int {
        return data.hashValue + getVersion(network: Network.get())
    }
    
    public static func fromString(_ address: String) throws -> Address {
        do {
            return try fromString(Network.get(), address)
        } catch {
            for network in Network.allCases {
                do {
                    if network != Network.get() {
                        throw PSBTError.message("Provided \(network.rawValue) address invalid on configured \(Network.get().rawValue) network: \(address). Use a \(network.rawValue) configuration to use this address.")
                    }
                    return try fromString(network, address)
                } catch {
                    //ignore
                }
            }

            throw error
        }
    }
    
    public static func fromString(_ network: Network, _ address: String) throws -> Address {
        if network.hasP2pkhAddressPrefix(address) || network.hasP2SHAddressPrefix(address) {
            do {
                guard let decodedBytes = address.base58CheckDecodedBytes else {
                    throw PSBTError.message("address base58CheckDecoded error")
                }
                if decodedBytes.count == 21 {
                    let version = Int(decodedBytes[0])
                    let hash = Array(decodedBytes[1..<21])
                    if version == network.p2pkhAddressHeader {
                        return P2PKHAddress(hash)
                    }
                    if version == network.p2shAddressHeader {
                        return P2SHAddress(hash)
                    }
                }
            } catch {
                
            }
        }
        
        if address.lowercased().hasPrefix(network.bech32AddressHrp) {
            let data = try Bech32().decodeM(address)
            if data.hrp == network.bech32AddressHrp {
                let witnessVersion = data.checksum.bytes[0]
                if witnessVersion == 0 {
                    if data.encoding != .bech32 {
                        throw PSBTError.message("Invalid address - witness version is 0 but encoding is \(data.encoding)")
                    }
                    
                    let convertedProgram = Array(data.checksum.bytes[1..<data.checksum.bytes.count])
                    guard let witnessProgram = Utils.bech32ConvertBits(from: 5, to: 8, pad: false, idata: convertedProgram) else {
                        throw PSBTError.message("bech32ConvertBits error")
                    }
                    if witnessProgram.count == 20 {
                        return P2WPKHAddress(witnessProgram.bytes)
                    }
                    if witnessProgram.count == 32 {
                        return P2WSHAddress(witnessProgram.bytes)
                    }
                } else if witnessVersion == 1 {
                    if data.encoding != .bech32m {
                        throw PSBTError.message("Invalid address - witness version is 1 but encoding is \(data.encoding)")
                    }
                    
                    let convertedProgram = Array(data.checksum.bytes[1..<data.checksum.bytes.count])
                    guard let witnessProgram = Utils.bech32ConvertBits(from: 5, to: 8, pad: false, idata: convertedProgram) else {
                        throw PSBTError.message("bech32ConvertBits error")
                    }
                    if witnessProgram.count == 32 {
                        return P2TRAddress(witnessProgram.bytes)
                    }
                }
            }
        }
        throw PSBTError.message("Could not parse invalid address " + address)
    }
}
