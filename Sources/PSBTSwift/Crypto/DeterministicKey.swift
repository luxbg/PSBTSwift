//
//  DeterministicKey.swift
//
//
//  Created by 薛跃杰 on 2024/2/22.
//

import Foundation
import BIP32Swift
import Base58Swift

public class DeterministicKey {
    public let node: HDNode?
    private let publicKey: Data?
    public let parent: DeterministicKey?
    public let childNumberPath: [ChildNumber]
    public var depth: Int
    public var parentFingerprint: [UInt8]
    public let chainCode: [UInt8]
    
    public init(parent: DeterministicKey?, publicKey: Data, childNumberPath: [ChildNumber], depth: Int, parentFingerprint: [UInt8], chainCode: [UInt8]) {
        self.publicKey = publicKey
        self.node = nil
        self.parent = parent
        self.depth = depth
        self.childNumberPath = childNumberPath
        self.parentFingerprint = parentFingerprint
        self.chainCode = chainCode
    }
    
    public init(parent: DeterministicKey?, priv: Data, childNumberPath: [ChildNumber], depth: Int, parentFingerprint: [UInt8], chainCode: [UInt8]) {
        var data = HDNode.HDversion().privatePrefix
        let depthData = Data([UInt8(depth)])
        data.append(depthData)
        data.append(Data(parentFingerprint))
        data.append(Data(chainCode))
        data.append(priv)
        let chacksum = data.sha256().sha256()
        data.append(chacksum)
        self.node = HDNode(data)
        self.parent = parent
        self.depth = depth
        self.childNumberPath = childNumberPath
        self.parentFingerprint = parentFingerprint
        self.chainCode = chainCode
        self.publicKey = nil
    }
    
    public init(parent: DeterministicKey?, publicKey: Data?, priv: Data?, childNumberPath: [ChildNumber], chainCode: [UInt8]) {
        var noParent = true
        if parent != nil {
            noParent = false
        } else {
            noParent = true
        }
        self.parent = parent
        self.childNumberPath = childNumberPath
        self.chainCode = chainCode
        self.depth = noParent ? 0 : parent!.depth + 1
        self.parentFingerprint = !noParent ? parent!.parentFingerprint : [UInt8](repeating: 0, count: 4)
        self.node = nil
        self.publicKey = publicKey
    }
    
    public init(parent: DeterministicKey?, priv: Data, childNumberPath: [ChildNumber], chainCode: [UInt8]) {
        var noParent = true
        if parent != nil {
            noParent = false
        } else {
            noParent = true
        }
        self.parent = parent
        self.childNumberPath = childNumberPath
        self.chainCode = chainCode
        self.depth = noParent ? 0 : parent!.depth + 1
        self.parentFingerprint = !noParent ? parent!.parentFingerprint : [UInt8](repeating: 0, count: 4)
        var data = HDNode.HDversion().privatePrefix
        let depthData = Data([UInt8(depth)])
        data.append(depthData)
        data.append(Data(parentFingerprint))
        data.append(Data(chainCode))
        data.append(priv)
        let chacksum = data.sha256().sha256()
        data.append(chacksum)
        self.node = HDNode(data)
        self.publicKey = nil
    }
    
    public func isPublicKeyOnly() -> Bool {
        guard let _ = publicKey else {
            return false
        }
        return true
    }
    
    public func hasPrivKey() -> Bool {
        guard let _ = node else {
            return false
        }
        return true
    }
    
    public func getPublickey() -> Data {
        if let _publicKey = publicKey {
            return _publicKey
        }
        return self.node!.publicKey
    }
    
    public func getIdentifier() -> Data {
        return Utils.sha256hash160(input: getPublickey().bytes)!
    }
    
    public func getFingerprint() -> Data {
        return getIdentifier().prefix(4)
    }
    
    public func getPrivKeyBytes33() -> Data? {
        guard let _privateKey = node?.privateKey else  {
            return nil
        }
        var bytes33 = Data(repeating: 0, count: 33)
        bytes33.replaceSubrange((33 - _privateKey.count)..<33, with: _privateKey)
        return bytes33
    }
    
    public func dropPrivateBytes() -> DeterministicKey {
        if isPublicKeyOnly() {
            return self
        } else {
            return DeterministicKey(parent: parent, publicKey: node!.publicKey, priv: nil, childNumberPath: childNumberPath, chainCode: chainCode)
        }
    }
    
    public func dropParent() -> DeterministicKey {
        let key = DeterministicKey(parent: nil, publicKey: publicKey, priv: node?.privateKey, childNumberPath: childNumberPath, chainCode: chainCode)
        key.parentFingerprint = parentFingerprint
        key.depth = depth
        return key
    }
    
    public func getChildNumber() -> ChildNumber {
        return childNumberPath.count == 0 ? ChildNumber.ZERO :childNumberPath[childNumberPath.count - 1]
    }
    
    public static func toBase58(ser: Data) -> String {
        return addChecksum(input: ser).bytes.base58EncodedString
    }
    
    static func addChecksum(input: Data) -> Data {
        var checksummed = Data()
        checksummed.append(input)
        let checksum = input.sha256().sha256()
        checksummed.append(checksum[..<4])
        return checksummed
    }
}
