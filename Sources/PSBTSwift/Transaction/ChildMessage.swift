//
//  ChildMessage.swift
//
//
//  Created by 薛跃杰 on 2024/1/18.
//

import Foundation

public class ChildMessage: Message {
    public var parent: Message?

    public override init() {
        super.init()
    }

    public init(rawtx: [UInt8], offset: Int) {
        super.init(payload: rawtx, offset: offset)
    }
    public func setParent(parent: Message?) {
        self.parent = parent
    }

    public override func adjustLength(adjustment: Int) {
        adjustLength(newArraySize: 0, adjustment: adjustment)
    }

    public override func adjustLength(newArraySize: Int, adjustment: Int) {
        super.adjustLength(newArraySize: newArraySize, adjustment: adjustment)

        parent?.adjustLength(newArraySize: newArraySize, adjustment: adjustment)
    }
}
