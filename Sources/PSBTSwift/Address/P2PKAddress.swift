//
//  P2PKAddress.swift
//
//
//  Created by 薛跃杰 on 2024/1/25.
//

import Foundation
import CryptoSwift

public class P2PKAddress: Address {
    public override init(_ data: [UInt8]) {
        super.init(data)
    }

    public override func getVersion(network: Network) -> Int {
        return network.p2pkhAddressHeader
    }

    public override func getAddress(network: Network) -> String {
        return data.toHexString()
    }

    public override func getScriptType() -> ScriptType {
        return .P2PK
    }

    public func getOutputScriptDataType() -> String {
        return "Public Key"
    }
}
