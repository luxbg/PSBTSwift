//
//  Script.swift
//
//
//  Created by 薛跃杰 on 2024/1/16.
//

import Foundation

public class Script {
    public static let MAX_SCRIPT_ELEMENT_SIZE: Int = 520

      // The program is a set of chunks where each element is either [opcode] or [data, data, data ...]
    var chunks: [ScriptChunk]
    
    var program: [UInt8]?
    
    public convenience init(programBytes: [UInt8]) throws {
        try self.init(programBytes: programBytes, parse: true)
    }
    
    public init(programBytes: [UInt8], parse: Bool) throws {
        program = programBytes
        self.chunks = [ScriptChunk]()
        if parse {
            do {
                try self.parse()
            } catch let error {
                throw PSBTError.message("Invalid script, continuing with already parsed chunks: \(error)")
            }
        }
    }
    
    public init(chunks: [ScriptChunk]) {
        self.chunks = chunks
    }
    
    public static let STANDARD_TRANSACTION_SCRIPT_CHUNKS: [ScriptChunk] = [
        ScriptChunk(opcode: ScriptOpCodes.OP_DUP, data: nil),
        ScriptChunk(opcode: ScriptOpCodes.OP_HASH160, data: nil),
        ScriptChunk(opcode: ScriptOpCodes.OP_EQUALVERIFY, data: nil),
        ScriptChunk(opcode: ScriptOpCodes.OP_CHECKSIG, data: nil),
    ]
    
    public func parse() throws {
        chunks = [ScriptChunk]()   // Common size.
        let bis = Data(program!)
        var index = 0
        while index < bis.count {
            let opcode = Int(bis[index])
            index += 1
            
            var dataToRead: Int = -1
            if opcode >= 0 && opcode < ScriptOpCodes.OP_PUSHDATA1 {
                // Read some bytes of data, where how many is the opcode value itself.
                dataToRead = opcode
            } else if opcode == ScriptOpCodes.OP_PUSHDATA1 {
                if bis.count - index < 1 {
                    throw PSBTError.message("Unexpected end of script - OP_PUSHDATA1 was followed by \(bis.count - index) bytes")
                }
                dataToRead = Int(bis[index])
                index += 1
            } else if opcode == ScriptOpCodes.OP_PUSHDATA2 {
                // Read a short, then read that many bytes of data.
                if bis.count - index < 2 {
                    throw PSBTError.message("Unexpected end of script - OP_PUSHDATA2 was followed by only \(bis.count - index) bytes")
                }
                dataToRead = try Utils.readUint16FromStream(bis.subdata(in: index..<index+2))
                index += 2
            } else if opcode == ScriptOpCodes.OP_PUSHDATA4 {
                // Read a uint32, then read that many bytes of data.
                // Though this is allowed, because its value cannot be > 520, it should never actually be used
                if bis.count - index < 4 {
                    throw PSBTError.message("Unexpected end of script - OP_PUSHDATA4 was followed by only \(bis.count - index) bytes")
                }
                dataToRead = try Utils.readUint32FromStream(bis.subdata(in: index..<index+4))
                index += 4
            }
            
            var chunk: ScriptChunk
            if dataToRead == -1 {
                chunk = ScriptChunk(opcode: opcode, data: nil)
            } else {
                if dataToRead > bis.count - index {
                    throw PSBTError.message("Push of data element that is larger than remaining data")
                }
                let data = Array(bis[index..<index+dataToRead])
                index += dataToRead
                
                chunk = ScriptChunk(opcode: opcode, data: data)
            }
            // Save some memory by eliminating redundant copies of the same chunk objects.
            for c in Script.STANDARD_TRANSACTION_SCRIPT_CHUNKS {
                if c.equals(chunk) { chunk = c }
            }
            chunks.append(chunk)
        }
    }
    
    public func getProgram() throws -> [UInt8] {
        if let _program = self.program, _program.count == 0 {
            return _program
        } else {
            var bos = Data()
            for chunk in chunks {
                try chunk.write(outData: &bos)
            }
            program = bos.bytes
            return bos.bytes
        }
    }

    public func getProgramAsHex() -> String {
        guard let _program = try? getProgram() else {
            return ""
        }
        return _program.toHexString()
    }

    public func isEmpty() -> Bool {
        return chunks.isEmpty
    }

    public func getChunks() -> [ScriptChunk] {
        return chunks
    }

    public func containsToAddress() throws -> Bool {
        for scriptType in ScriptType.allCases {
            if try scriptType.isScriptType(script: self) {
                return true
            }
        }
        return false
    }

    public func getPubKey() throws -> Data {
        for scriptType in ScriptType.SINGLE_KEY_TYPES {
            if try scriptType.isScriptType(script:self) {
                return try scriptType.getPublicKeyFromScript(script: self)
            }
        }
        throw PSBTError.message("Script not a standard form that contains a single key")
    }

    public func getPubKeyHash() throws -> [UInt8] {
        for scriptType in ScriptType.SINGLE_HASH_TYPES {
            if try scriptType.isScriptType(script: self) {
                return try scriptType.getHashFromScript(script: self)
            }
        }
        throw PSBTError.message("Script not a standard form that contains a single hash")
    }
    
    public func getToAddress() -> Address? {
        do {
            return try getToAddresses().first
        } catch {
            return nil
        }
    }

    public func getToAddresses() throws -> [Address] {
        for scriptType in ScriptType.SINGLE_HASH_TYPES {
            if try scriptType.isScriptType(script: self) {
                return [try scriptType.getAddress(pubKey: scriptType.getHashFromScript(script: self))]
            }
        }

        if try ScriptType.P2TR.isScriptType(script: self) {
            let publicKey = try ScriptType.P2TR.getPublicKeyFromScript(script: self)
            
            return [P2TRAddress(Utils.getDataXCoord(publicKey)!.bytes)]
        }

        for scriptType in ScriptType.SINGLE_KEY_TYPES {
            if try scriptType.isScriptType(script: self) {
                return [try scriptType.getAddress(pubKey: scriptType.getPublicKeyFromScript(script: self).bytes)]
            }
        }

        if try ScriptType.MULTISIG.isScriptType(script: self) {
            var addresses = [Address]()
            let pubKeys = try ScriptType.MULTISIG.getPublicKeysFromScript(script: self)
            for pubKey in pubKeys {
                addresses.append(P2PKAddress(pubKey.bytes))
            }
            return addresses
        }

        throw PSBTError.message("Cannot find addresses in non standard script: \(self)")
    }

    public func getNumRequiredSignatures() throws -> Int {
        if try ScriptType.P2PK.isScriptType(script: self) || ScriptType.P2PKH.isScriptType(script: self) || ScriptType.P2WPKH.isScriptType(script: self) || ScriptType.P2TR.isScriptType(script: self) {
            return 1
        }

        if try ScriptType.MULTISIG.isScriptType(script: self) {
            return try ScriptType.MULTISIG.getThreshold(script: self)
        }

        throw PSBTError.message("Cannot find number of required signatures for script: \(self)")
    }
    
    public func getFirstNestedScript() throws -> Script? {
        for chunk in chunks {
            if chunk.isScript() {
                return try Script(programBytes: chunk.data!)
            }
        }
        return nil
    }

    public func getSignatures() throws -> [TransactionSignature] {
        var signatures = [TransactionSignature]()
        for chunk in chunks {
            if chunk.isSignature() {
                signatures.append(try chunk.getSignature())
            }
        }
        return signatures
    }

    public static func decodeFromOpN(_ opcode: Int) throws -> Int {
        if (opcode != ScriptOpCodes.OP_0 && opcode != ScriptOpCodes.OP_1NEGATE) && (opcode < ScriptOpCodes.OP_1 || opcode > ScriptOpCodes.OP_16) {
            throw PSBTError.message("decodeFromOpN called on non OP_N opcode: \(opcode)")
        }

        if opcode == ScriptOpCodes.OP_0 {
            return 0
        } else if opcode == ScriptOpCodes.OP_1NEGATE {
            return -1
        } else {
            return opcode + 1 - ScriptOpCodes.OP_1
        }
    }

    public static func encodeToOpN(_ value: Int) throws -> Int {
        if value < -1 || value > 16 {
            throw PSBTError.message("encodeToOpN called for \(value) which we cannot encode in an opcode.")
        }
        if value == 0 {
            return ScriptOpCodes.OP_0
        } else if value == -1 {
            return ScriptOpCodes.OP_1NEGATE
        } else {
            return value - 1 + ScriptOpCodes.OP_1
        }
    }

    public static func removeAllInstancesOfOp(_ inputScript: [UInt8], _ opCode: Int) -> [UInt8] {
        return removeAllInstancesOf(inputScript, [(UInt8)(opCode)])
    }

    public static func removeAllInstancesOf(_ inputScript: [UInt8], _ chunkToRemove: [UInt8]) -> [UInt8] {
        var bos = [UInt8]()
        var cursor = 0
        while cursor < inputScript.count {
            let skip = inputScript[cursor..<cursor+chunkToRemove.count].elementsEqual(chunkToRemove)

            let opcode = inputScript[cursor]
            cursor += 1
            var additionalBytes = 0
            if opcode >= 0 && opcode < ScriptOpCodes.OP_PUSHDATA1 {
                additionalBytes = Int(opcode)
            } else if opcode == ScriptOpCodes.OP_PUSHDATA1 {
                additionalBytes = Int(inputScript[cursor]) + 1
            } else if opcode == ScriptOpCodes.OP_PUSHDATA2 {
                additionalBytes = Utils.readUint16(inputScript, offset: cursor) + 2
            } else if opcode == ScriptOpCodes.OP_PUSHDATA4 {
                additionalBytes = Int(Utils.readUint32(bytes: inputScript, offset: cursor)) + 4
            }
            if !skip {
                bos.append(opcode)
                bos.append(contentsOf: inputScript[cursor..<cursor+additionalBytes])
            }
            cursor += additionalBytes
        }
        return bos
    }
    
    private static func equalsRange(_ a: [UInt8], start: Int, _ b: [UInt8]) -> Bool {
        if start + b.count > a.count {
            return false
        }
        for i in 0..<b.count {
            if a[i + start] != b[i] {
                return false
            }
        }
        return true
    }

    public func toString() -> String {
        var builder = ""
        for chunk in chunks {
            builder.append("\(chunk.toString()) ")
        }
        return builder.trimmingCharacters(in: .whitespaces)
    }

    public func toDisplayString() throws -> String {
        return try Script.toDisplayString(chunks)
    }

    public static func toDisplayString(_ scriptChunks: [ScriptChunk]) throws -> String {
        var builder = ""
        var signatureCount = 1
        var pubKeyCount = 1
        for chunk in scriptChunks {
            if chunk.isSignature() {
                builder.append("<signature\(signatureCount)> ")
                signatureCount += 1
            } else if chunk.isScript() {
                let nestedScript = try chunk.getScript()
                if try ScriptType.P2WPKH.isScriptType(script: nestedScript!) {
                    builder.append("(OP_0 <wpkh>) ")
                } else if try ScriptType.P2WSH.isScriptType(script: nestedScript!) {
                    builder.append("(OP_0 <wsh>) ")
                } else {
                    let string = try nestedScript?.toDisplayString()
                    builder.append("(\(string ?? "")) ")
                }
            } else if chunk.isPubKey() {
                builder.append("<pubkey\(pubKeyCount)> ")
                pubKeyCount += 1
            } else {
                builder.append("\(chunk.toString()) ")
            }
        }
        return builder.trimmingCharacters(in: .whitespaces)
    }

    public func isEqual(_ object: Any?) throws -> Bool {
        guard let other = object as? Script, let otherQuickProgram = try? other.getQuickProgram() else {
            return false
        }
        return try getQuickProgram() == otherQuickProgram
    }

    public func getHash() throws -> Int {
        return try getQuickProgram().hashValue
    }

    private func getQuickProgram() throws -> [UInt8]? {
        if let program = self.program {
            return program
        }
        return try getProgram()
    }
}
