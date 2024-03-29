//
//  Network.swift
//
//
//  Created by 薛跃杰 on 2024/1/25.
//

import Foundation

public enum Network: String, CaseIterable, Equatable {
    case mainnet = "mainnet"
    case testnet = "testnet"
    case regtest = "regtest"
    case signet = "signet"
    
    public static var currentNetwork = Network.mainnet
    
    public static let blockHeightProperty = "com.sparrowwallet.blockHeight"
    
    var p2pkhAddressHeader: Int {
        switch self {
        case .mainnet:
            return 0
        case .testnet, .regtest, .signet:
            return 111
        }
    }
    
    var p2pkhAddressPrefix: String {
        switch self {
        case .mainnet:
            return "1"
        case .testnet, .regtest, .signet:
            return "mn"
        }
    }
    
    var p2shAddressHeader: Int {
        switch self {
        case .mainnet:
            return 5
        case .testnet, .regtest, .signet:
            return 196
        }
    }
    
    var p2shAddressPrefix: String {
        switch self {
        case .mainnet:
            return "3"
        case .testnet, .regtest:
            return "2"
        case .signet:
            return "tb"
        }
    }
    
    var bech32AddressHrp: String {
        switch self {
        case .mainnet:
            return "bc"
        case .testnet, .regtest:
            return "tb"
        case .signet:
            return "bcrt"
        }
    }
    
    var xprvHeader: Header {
        switch self {
        case .mainnet:
            return .xprv
        case .testnet, .regtest, .signet:
            return .tprv
        }
    }
    
    var xpubHeader: Header {
        switch self {
        case .mainnet:
            return .xpub
        case .testnet, .regtest, .signet:
            return .tpub
        }
    }
    
    var dumpedPrivateKeyHeader: Int {
        switch self {
        case .mainnet:
            return 128
        case .testnet, .regtest, .signet:
            return 239
        }
    }
    
    var defaultPort: Int {
        switch self {
        case .mainnet:
            return 8332
        case .testnet:
            return 18332
        case .regtest:
            return 18443
        case .signet:
            return 38332
        }
    }

    public static func get() -> Network {
        return currentNetwork
    }

    public static func set(network: Network) {
        currentNetwork = network
    }
    
    public func hasP2pkhAddressPrefix(_ address: String) -> Bool {
        if address.hasPrefix(self.p2pkhAddressPrefix) {
            return true
        }
        return false
    }
    
    public func hasP2SHAddressPrefix(_ address: String) -> Bool {
        if address.hasPrefix(self.p2shAddressPrefix) {
            return true
        }
        return false
    }
}
