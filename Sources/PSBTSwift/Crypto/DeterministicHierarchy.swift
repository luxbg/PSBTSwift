//
//  DeterministicHierarchy.swift
//
//
//  Created by 薛跃杰 on 2024/2/22.
//

import Foundation
import Secp256k1Swift

public class DeterministicHierarchy {
    private var keys = [[ChildNumber]: DeterministicKey]()
    private var rootPath: [ChildNumber]
    private var lastChildNumbers = [[ChildNumber]: ChildNumber]()

    public init(rootKey: DeterministicKey) {
        rootPath = rootKey.childNumberPath
        putKey(key: rootKey)
    }

    public final func putKey(key: DeterministicKey) {
        let path = key.childNumberPath
        let parent = key.parent
        if let _parent = parent {
            lastChildNumbers[_parent.childNumberPath] = key.getChildNumber()
        }
        keys[path] = key
    }

    public func get(path: [ChildNumber]) throws -> DeterministicKey {
        if keys[path] == nil {
            if path.count == 0 {
                throw PSBTError.message("Can't derive the master key: nothing to derive from.")
            }

            let parent = try get(path: Array(path[0..<path.count - 1]))
            putKey(key: try HDKeyDerivation.deriveChildKey(parent: parent, childNumber: path[path.count - 1]))
        }

        return keys[path]!
    }
}
