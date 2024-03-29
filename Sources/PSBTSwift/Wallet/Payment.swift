//
//  Payment.swift
//
//
//  Created by 薛跃杰 on 2024/2/28.
//

import Foundation

public class Payment {
    public var address: Address
    public var label: String
    public var amount: Int64
    public var sendMax: Bool
    public var type: PaymentType

    public convenience init(address: Address, label: String, amount: Int64, sendMax: Bool) {
        self.init(address: address, label: label, amount: amount, sendMax: sendMax, type: .DEFAULT)
    }

    public init(address: Address, label: String, amount: Int64, sendMax: Bool, type: PaymentType) {
        self.address = address
        self.label = label
        self.amount = amount
        self.sendMax = sendMax
        self.type = type
    }
    
    public enum PaymentType {
        case DEFAULT
        case WHIRLPOOL_FEE
        case FAKE_MIX
        case MIX
    }
}

