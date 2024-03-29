//
//  P2PKHAddress.swift
//
//
//  Created by 薛跃杰 on 2024/1/25.
//

import Foundation

public class P2PKHAddress: Address {
    public override init(_ data: [UInt8]) {
        super.init(data)
    }

    public override func getVersion(network: Network) -> Int {
        return network.p2pkhAddressHeader
    }

    public override func getScriptType() -> ScriptType {
        return .P2PKH
    }

    public func getOutputScriptDataType() -> String {
        return "Public Key Hash"
    }
}
