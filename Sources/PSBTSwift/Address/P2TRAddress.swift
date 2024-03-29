//
//  P2TRAddress.swift
//
//
//  Created by 薛跃杰 on 2024/1/25.
//

import Foundation
import Bech32

public class P2TRAddress: Address {
    public override init(_ data: [UInt8]) {
        super.init(data)
    }

    public override func getVersion(network: Network) -> Int {
        return 1
    }
    
    public override func getAddress(network: Network) -> String {
        return Bech32().encode(network.bech32AddressHrp, values: Data(data), encoding: Bech32.Encoding.bech32m)
    }

    public override func getScriptType() -> ScriptType {
        return .P2TR
    }

    public func getOutputScriptDataType() -> String {
        return "Taproot"
    }
}
