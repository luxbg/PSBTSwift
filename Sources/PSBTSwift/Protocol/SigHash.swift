//
//  SigHash.swift
//
//
//  Created by 薛跃杰 on 2024/1/18.
//

import Foundation

public enum SigHash: UInt8, CaseIterable {
    case ALL = 1
    case NONE = 2
    case SINGLE = 3
    case ANYONECANPAY = 0x80
    case ANYONECANPAY_ALL = 0x81
    case ANYONECANPAY_NONE = 0x82
    case ANYONECANPAY_SINGLE = 0x83
    case DEFAULTType = 0

    public static let legacySigningTypes: [SigHash] = [.ALL, .NONE, .SINGLE, .ANYONECANPAY_ALL, .ANYONECANPAY_NONE, .ANYONECANPAY_SINGLE]
    public static let taprootSigningTypes: [SigHash] = [.DEFAULTType, .ALL, .NONE, .SINGLE, .ANYONECANPAY_ALL, .ANYONECANPAY_NONE, .ANYONECANPAY_SINGLE]

    public var name: String {
        switch self {
        case .ALL:
            return "ALL"
        case .NONE:
            return "None"
        case .SINGLE:
            return "Single"
        case .ANYONECANPAY:
            return "Anyone Can Pay"
        case .ANYONECANPAY_ALL:
            return "ALL + Anyone Can Pay"
        case .ANYONECANPAY_NONE:
            return "None + Anyone Can Pay"
        case .ANYONECANPAY_SINGLE:
            return "Single + Anyone Can Pay"
        case .DEFAULTType:
            return "Default"
        }
    }

    public var byteValue: UInt8 {
        return self.rawValue
    }

    public var intValue: Int {
        return Int(self.rawValue)
    }

    public func anyoneCanPay() -> Bool {
        return (self.rawValue & SigHash.ANYONECANPAY.rawValue) != 0
    }

    public static func fromByte(_ sigHashByte: UInt8) -> SigHash? {
        return SigHash(rawValue: sigHashByte)
    }

    public func toString() -> String {
        return self.name
    }
}
