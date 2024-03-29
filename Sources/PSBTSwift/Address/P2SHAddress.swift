//
//  P2SHAddress.swift
//
//
//  Created by 薛跃杰 on 2024/1/25.
//

import Foundation

public class P2SHAddress: Address {
    public override init(_ data: [UInt8]) {
        super.init(data)
    }

    public override func getVersion(network: Network) -> Int {
        return network.p2shAddressHeader
    }

    public override func getScriptType() -> ScriptType {
        return .P2SH
    }

    public func getOutputScriptDataType() -> String {
        return "Script Hash"
    }
    
    public func fromProgram(program: [UInt8]) -> P2SHAddress? {
        guard let input = Utils.sha256hash160(input: program)?.bytes else {
            return nil
        }
        return P2SHAddress(input)
    }
}
