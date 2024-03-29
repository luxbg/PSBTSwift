//
//  File.swift
//  PSBTSwift
//
//  Created by 薛跃杰 on 2024/2/21.
//

import Foundation

public enum PolicyType: String {
    case SINGLE = "Single Signature"
    case MULTI = "Multi Signature"
    case CUSTOM = "Custom"

    private var defaultScriptType: String {
        switch self {
        case .SINGLE:
            return "P2WPKH"
        case .MULTI, .CUSTOM:
            return "P2WSH"
        }
    }

    public func getName() -> String {
        return self.rawValue
    }

    public func getDefaultScriptType() -> String {
        return self.defaultScriptType
    }
}
