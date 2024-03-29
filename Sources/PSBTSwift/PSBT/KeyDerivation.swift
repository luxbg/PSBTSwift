//
//  KeyDerivation.swift
//
//
//  Created by 薛跃杰 on 2024/2/19.
//

import Foundation

public class KeyDerivation: Hashable, Equatable {
    
    public let masterFingerprint: String?
    public let derivationPath: String?
    public var derivation: [ChildNumber]?

    public init(masterFingerprint: String?, derivation: [ChildNumber]) {
        self.masterFingerprint = masterFingerprint?.lowercased()
        self.derivationPath = KeyDerivation.writePath(pathList: derivation)
        self.derivation = derivation
    }

    public init(masterFingerprint: String?, derivationPath: String?) throws {
        self.masterFingerprint = masterFingerprint?.lowercased()
        self.derivationPath = derivationPath
        self.derivation = try KeyDerivation.parsePath(path: derivationPath)
    }

    public func getMasterFingerprint() -> String? {
        return masterFingerprint
    }

    public func getDerivationPath() -> String? {
        return derivationPath
    }

    public func getDerivation() throws -> [ChildNumber]? {
        if derivation == nil {
            derivation = try KeyDerivation.parsePath(path: derivationPath)
        }
        return derivation
    }

    public func extend(extensionN: ChildNumber) throws -> KeyDerivation {
        return try extend(extension: [extensionN])
    }

    public func extend(extension: [ChildNumber]) throws -> KeyDerivation {
        var extendedDerivation = try getDerivation()
        extendedDerivation?.append(contentsOf: `extension`)
        return KeyDerivation(masterFingerprint: masterFingerprint, derivation: extendedDerivation ?? [])
    }

    public static func parsePath(path: String?) throws -> [ChildNumber] {
        return try parsePath(path: path, wildcardReplacement: 0)
    }

    public static func parsePath(path: String?, wildcardReplacement: Int) throws -> [ChildNumber] {
        var nodes = [ChildNumber]()
         guard let path = path else {
             return nodes
         }
         let parsedNodes = path.replacingOccurrences(of: "M", with: "").replacingOccurrences(of: "m", with: "").split(separator: "/")
         for node in parsedNodes {
             var n = node.replacingOccurrences(of: " ", with: "")
             if n.isEmpty {
                 continue
             }
             let isHard = n.hasSuffix("H") || n.hasSuffix("h") || n.hasSuffix("'")
             if isHard {
                 n = String(n.dropLast())
             }
             if n == "*" {
                 n = String(wildcardReplacement)
             }
             if let nodeNumber = Int(n) {
                 do {
                     nodes.append(try ChildNumber(childNumber: nodeNumber, isHardened: isHard))
                 } catch let error {
                     throw error
                 }
             }
         }
         return nodes
    }

    public static func writePath(pathList: [ChildNumber]) -> String {
        return writePath(pathList: pathList, useApostrophes: true)
    }

    public static func writePath(pathList: [ChildNumber], useApostrophes: Bool) -> String {
        var path = "m"
        for child in pathList {
            path.append("/")
            path.append(child.toString(useApostrophes: useApostrophes))
        }
        return path
    }

    public static func isValid(derivationPath: String?) -> Bool {
        do {
            let _ = try parsePath(path: derivationPath)
            return true
        } catch {
            return false
        }
    }

    public static func getBip47Derivation(account: Int) throws -> [ChildNumber] {
        return [
            try ChildNumber(childNumber: 47, isHardened: true),
            try ChildNumber(childNumber: Network.get() == .mainnet ? 0 : 1, isHardened: true),
            try ChildNumber(childNumber: max(0, account), isHardened: true)
        ]
    }

    public func copy() throws -> KeyDerivation {
        return try KeyDerivation(masterFingerprint: masterFingerprint, derivationPath: derivationPath)
    }

    public func toString() -> String {
        return (masterFingerprint ?? "") + (derivationPath != nil ? derivationPath!.replacingOccurrences(of: "m", with: "") : "")
    }
    
    public static func == (lhs: KeyDerivation, rhs: KeyDerivation) -> Bool {
        return lhs.toString() == lhs.toString()
    }

    public var hashValue: Int {
        return toString().hashValue
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(masterFingerprint ?? "")
        hasher.combine(derivationPath ?? "")
        hasher.combine(derivation?.hashValue ?? 0)
    }
}
