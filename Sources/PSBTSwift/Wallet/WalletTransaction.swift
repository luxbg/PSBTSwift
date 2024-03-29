//
//  WalletTransaction.swift
//
//
//  Created by 薛跃杰 on 2024/2/27.
//

import Foundation

public class WalletTransaction {
//    public let wallet: Wallet
    public let transaction: Transaction
    public let utxoSelectors: [UtxoSelector]
//    public let selectedUtxoSets: [[BlockTransactionHashIndex: WalletNode]]
    public let payments: [Payment]
//    public let changeMap: [WalletNode: Int64]
    public let fee: Int64
    public let inputTransactions: [[UInt8]: BlockTransaction]
    
    public init(transaction: Transaction, utxoSelectors: [UtxoSelector], payments: [Payment], fee: Int64) {
        self.transaction = transaction
        self.utxoSelectors = utxoSelectors
//        self.selectedUtxoSets = selectedUtxoSets
        self.payments = payments
//        self.changeMap = [:]
        self.fee = fee
        self.inputTransactions = [:]
    }
    
//    public init(transaction: Transaction, utxoSelectors: [UtxoSelector], payments: [Payment], fee: Int64) {
////        self.wallet = wallet
//        self.transaction = transaction
//        self.utxoSelectors = utxoSelectors
////        self.selectedUtxoSets = selectedUtxoSets
//        self.payments = payments
////        self.changeMap = changeMap
//        self.fee = fee
//        self.inputTransactions = [:]
//    }
    
    public init(transaction: Transaction, utxoSelectors: [UtxoSelector], payments: [Payment], fee: Int64, inputTransactions: [[UInt8]: BlockTransaction]) {
        self.transaction = transaction
        self.utxoSelectors = utxoSelectors
//        self.selectedUtxoSets = selectedUtxoSets
        self.payments = payments
//        self.changeMap = changeMap
        self.fee = fee
        self.inputTransactions = inputTransactions
    }
    
//    public func createPSBT() -> PSBT {
//        return PSBT(wallettransaction: self)
//    }
}
