//
//  ScriptOpCodes.swift
//
//
//  Created by 薛跃杰 on 2024/1/16.
//

import Foundation

public struct ScriptOpCodes {
    public static var OP_0 = 0x00 // push empty vector
    public static var OP_FALSE = OP_0
    public static var OP_PUSHDATA1 = 0x4c
    public static var OP_PUSHDATA2 = 0x4d
    public static var OP_PUSHDATA4 = 0x4e
    public static var OP_1NEGATE = 0x4f
    public static var OP_RESERVED = 0x50
    public static var OP_1 = 0x51
    public static var OP_TRUE = OP_1
    public static var OP_2 = 0x52
    public static var OP_3 = 0x53
    public static var OP_4 = 0x54
    public static var OP_5 = 0x55
    public static var OP_6 = 0x56
    public static var OP_7 = 0x57
    public static var OP_8 = 0x58
    public static var OP_9 = 0x59
    public static var OP_10 = 0x5a
    public static var OP_11 = 0x5b
    public static var OP_12 = 0x5c
    public static var OP_13 = 0x5d
    public static var OP_14 = 0x5e
    public static var OP_15 = 0x5f
    public static var OP_16 = 0x60
    
    // control
    public static var OP_NOP = 0x61
    public static var OP_VER = 0x62
    public static var OP_IF = 0x63
    public static var OP_NOTIF = 0x64
    public static var OP_VERIF = 0x65
    public static var OP_VERNOTIF = 0x66
    public static var OP_ELSE = 0x67
    public static var OP_ENDIF = 0x68
    public static var OP_VERIFY = 0x69
    public static var OP_RETURN = 0x6a
    
    // stack ops
    public static var OP_TOALTSTACK = 0x6b
    public static var OP_FROMALTSTACK = 0x6c
    public static var OP_2DROP = 0x6d
    public static var OP_2DUP = 0x6e
    public static var OP_3DUP = 0x6f
    public static var OP_2OVER = 0x70
    public static var OP_2ROT = 0x71
    public static var OP_2SWAP = 0x72
    public static var OP_IFDUP = 0x73
    public static var OP_DEPTH = 0x74
    public static var OP_DROP = 0x75
    public static var OP_DUP = 0x76
    public static var OP_NIP = 0x77
    public static var OP_OVER = 0x78
    public static var OP_PICK = 0x79
    public static var OP_ROLL = 0x7a
    public static var OP_ROT = 0x7b
    public static var OP_SWAP = 0x7c
    public static var OP_TUCK = 0x7d
    
    // splice ops
    public static var OP_CAT = 0x7e
    public static var OP_SUBSTR = 0x7f
    public static var OP_LEFT = 0x80
    public static var OP_RIGHT = 0x81
    public static var OP_SIZE = 0x82
    
    // bit logic
    public static var OP_INVERT = 0x83
    public static var OP_AND = 0x84
    public static var OP_OR = 0x85
    public static var OP_XOR = 0x86
    public static var OP_EQUAL = 0x87
    public static var OP_EQUALVERIFY = 0x88
    public static var OP_RESERVED1 = 0x89
    public static var OP_RESERVED2 = 0x8a
    
    // numeric
    public static var OP_1ADD = 0x8b
    public static var OP_1SUB = 0x8c
    public static var OP_2MUL = 0x8d
    public static var OP_2DIV = 0x8e
    public static var OP_NEGATE = 0x8f
    public static var OP_ABS = 0x90
    public static var OP_NOT = 0x91
    public static var OP_0NOTEQUAL = 0x92
    public static var OP_ADD = 0x93
    public static var OP_SUB = 0x94
    public static var OP_MUL = 0x95
    public static var OP_DIV = 0x96
    public static var OP_MOD = 0x97
    public static var OP_LSHIFT = 0x98
    public static var OP_RSHIFT = 0x99
    public static var OP_BOOLAND = 0x9a
    public static var OP_BOOLOR = 0x9b
    public static var OP_NUMEQUAL = 0x9c
    public static var OP_NUMEQUALVERIFY = 0x9d
    public static var OP_NUMNOTEQUAL = 0x9e
    public static var OP_LESSTHAN = 0x9f
    public static var OP_GREATERTHAN = 0xa0
    public static var OP_LESSTHANOREQUAL = 0xa1
    public static var OP_GREATERTHANOREQUAL = 0xa2
    public static var OP_MIN = 0xa3
    public static var OP_MAX = 0xa4
    public static var OP_WITHIN = 0xa5
    
    // crypto
    public static var OP_RIPEMD160 = 0xa6
    public static var OP_SHA1 = 0xa7
    public static var OP_SHA256 = 0xa8
    public static var OP_HASH160 = 0xa9
    public static var OP_HASH256 = 0xaa
    public static var OP_CODESEPARATOR = 0xab
    public static var OP_CHECKSIG = 0xac
    public static var OP_CHECKSIGVERIFY = 0xad
    public static var OP_CHECKMULTISIG = 0xae
    public static var OP_CHECKMULTISIGVERIFY = 0xaf
    
    // block state
    public static var OP_CHECKLOCKTIMEVERIFY = 0xb1
    
    // expansion
    public static var OP_NOP1 = 0xb0
    public static var OP_NOP2 = OP_CHECKLOCKTIMEVERIFY
    public static var OP_NOP3 = 0xb2
    public static var OP_NOP4 = 0xb3
    public static var OP_NOP5 = 0xb4
    public static var OP_NOP6 = 0xb5
    public static var OP_NOP7 = 0xb6
    public static var OP_NOP8 = 0xb7
    public static var OP_NOP9 = 0xb8
    public static var OP_NOP10 = 0xb9
    public static var OP_INVALIDOPCODE = 0xff
    
    private static var opCodeMap: [Int: String] = [
        OP_0: "0",
        OP_PUSHDATA1: "PUSHDATA1",
        OP_PUSHDATA2: "PUSHDATA2",
        OP_PUSHDATA4: "PUSHDATA4",
        OP_1NEGATE: "1NEGATE",
        OP_RESERVED: "RESERVED",
        OP_1: "1",
        OP_2: "2",
        OP_3: "3",
        OP_4: "4",
        OP_5: "5",
        OP_6: "6",
        OP_7: "7",
        OP_8: "8",
        OP_9: "9",
        OP_10: "10",
        OP_11: "11",
        OP_12: "12",
        OP_13: "13",
        OP_14: "14",
        OP_15: "15",
        OP_16: "16",
        OP_NOP: "NOP",
        OP_VER: "VER",
        OP_IF: "IF",
        OP_NOTIF: "NOTIF",
        OP_VERIF: "VERIF",
        OP_VERNOTIF: "VERNOTIF",
        OP_ELSE: "ELSE",
        OP_ENDIF: "ENDIF",
        OP_VERIFY: "VERIFY",
        OP_RETURN: "RETURN",
        OP_TOALTSTACK: "TOALTSTACK",
        OP_FROMALTSTACK: "FROMALTSTACK",
        OP_2DROP: "2DROP",
        OP_2DUP: "2DUP",
        OP_3DUP: "3DUP",
        OP_2OVER: "2OVER",
        OP_2ROT: "2ROT",
        OP_2SWAP: "2SWAP",
        OP_IFDUP: "IFDUP",
        OP_DEPTH: "DEPTH",
        OP_DROP: "DROP",
        OP_DUP: "DUP",
        OP_NIP: "NIP",
        OP_OVER: "OVER",
        OP_PICK: "PICK",
        OP_ROLL: "ROLL",
        OP_ROT: "ROT",
        OP_SWAP: "SWAP",
        OP_TUCK: "TUCK",
        OP_CAT: "CAT",
        OP_SUBSTR: "SUBSTR",
        OP_LEFT: "LEFT",
        OP_RIGHT: "RIGHT",
        OP_SIZE: "SIZE",
        OP_INVERT: "INVERT",
        OP_AND: "AND",
        OP_OR: "OR",
        OP_XOR: "XOR",
        OP_EQUAL: "EQUAL",
        OP_EQUALVERIFY: "EQUALVERIFY",
        OP_RESERVED1: "RESERVED1",
        OP_RESERVED2: "RESERVED2",
        OP_1ADD: "1ADD",
        OP_1SUB: "1SUB",
        OP_2MUL: "2MUL",
        OP_2DIV: "2DIV",
        OP_NEGATE: "NEGATE",
        OP_ABS: "ABS",
        OP_NOT: "NOT",
        OP_0NOTEQUAL: "0NOTEQUAL",
        OP_ADD: "ADD",
        OP_SUB: "SUB",
        OP_MUL: "MUL",
        OP_DIV: "DIV",
        OP_MOD: "MOD",
        OP_LSHIFT: "LSHIFT",
        OP_RSHIFT: "RSHIFT",
        OP_BOOLAND: "BOOLAND",
        OP_BOOLOR: "BOOLOR",
        OP_NUMEQUAL: "NUMEQUAL",
        OP_NUMEQUALVERIFY: "NUMEQUALVERIFY",
        OP_NUMNOTEQUAL: "NUMNOTEQUAL",
        OP_LESSTHAN: "LESSTHAN",
        OP_GREATERTHAN: "GREATERTHAN",
        OP_LESSTHANOREQUAL: "LESSTHANOREQUAL",
        OP_GREATERTHANOREQUAL: "GREATERTHANOREQUAL",
        OP_MIN: "MIN",
        OP_MAX: "MAX",
        OP_WITHIN: "WITHIN",
        OP_RIPEMD160: "RIPEMD160",
        OP_SHA1: "SHA1",
        OP_SHA256: "SHA256",
        OP_HASH160: "HASH160",
        OP_HASH256: "HASH256",
        OP_CODESEPARATOR: "CODESEPARATOR",
        OP_CHECKSIG: "CHECKSIG",
        OP_CHECKSIGVERIFY: "CHECKSIGVERIFY",
        OP_CHECKMULTISIG: "CHECKMULTISIG",
        OP_CHECKMULTISIGVERIFY: "CHECKMULTISIGVERIFY",
        OP_NOP1: "NOP1",
        OP_CHECKLOCKTIMEVERIFY: "CHECKLOCKTIMEVERIFY",
        OP_NOP3: "NOP3",
        OP_NOP4: "NOP4",
        OP_NOP5: "NOP5",
        OP_NOP6: "NOP6",
        OP_NOP7: "NOP7",
        OP_NOP8: "NOP8",
        OP_NOP9: "NOP9",
        OP_NOP10: "NOP10",
    ]
    
    private static var opCodeNameMap: [String: Int] = [
        "0": OP_0,
        "PUSHDATA1": OP_PUSHDATA1,
        "PUSHDATA2": OP_PUSHDATA2,
        "PUSHDATA4": OP_PUSHDATA4,
        "1NEGATE": OP_1NEGATE,
        "RESERVED": OP_RESERVED,
        "1": OP_1,
        "2": OP_2,
        "3": OP_3,
        "4": OP_4,
        "5": OP_5,
        "6": OP_6,
        "7": OP_7,
        "8": OP_8,
        "9": OP_9,
        "10": OP_10,
        "11": OP_11,
        "12": OP_12,
        "13": OP_13,
        "14": OP_14,
        "15": OP_15,
        "16": OP_16,
        "NOP": OP_NOP,
        "VER": OP_VER,
        "IF": OP_IF,
        "NOTIF": OP_NOTIF,
        "VERIF": OP_VERIF,
        "VERNOTIF": OP_VERNOTIF,
        "ELSE": OP_ELSE,
        "ENDIF": OP_ENDIF,
        "VERIFY": OP_VERIFY,
        "RETURN": OP_RETURN,
        "TOALTSTACK": OP_TOALTSTACK,
        "FROMALTSTACK": OP_FROMALTSTACK,
        "2DROP": OP_2DROP,
        "2DUP": OP_2DUP,
        "3DUP": OP_3DUP,
        "2OVER": OP_2OVER,
        "2ROT": OP_2ROT,
        "2SWAP": OP_2SWAP,
        "IFDUP": OP_IFDUP,
        "DEPTH": OP_DEPTH,
        "DROP": OP_DROP,
        "DUP": OP_DUP,
        "NIP": OP_NIP,
        "OVER": OP_OVER,
        "PICK": OP_PICK,
        "ROLL": OP_ROLL,
        "ROT": OP_ROT,
        "SWAP": OP_SWAP,
        "TUCK": OP_TUCK,
        "CAT": OP_CAT,
        "SUBSTR": OP_SUBSTR,
        "LEFT": OP_LEFT,
        "RIGHT": OP_RIGHT,
        "SIZE": OP_SIZE,
        "INVERT": OP_INVERT,
        "AND": OP_AND,
        "OR": OP_OR,
        "XOR": OP_XOR,
        "EQUAL": OP_EQUAL,
        "EQUALVERIFY": OP_EQUALVERIFY,
        "RESERVED1": OP_RESERVED1,
        "RESERVED2": OP_RESERVED2,
        "1ADD": OP_1ADD,
        "1SUB": OP_1SUB,
        "2MUL": OP_2MUL,
        "2DIV": OP_2DIV,
        "NEGATE": OP_NEGATE,
        "ABS": OP_ABS,
        "NOT": OP_NOT,
        "0NOTEQUAL": OP_0NOTEQUAL,
        "ADD": OP_ADD,
        "SUB": OP_SUB,
        "MUL": OP_MUL,
        "DIV": OP_DIV,
        "MOD": OP_MOD,
        "LSHIFT": OP_LSHIFT,
        "RSHIFT": OP_RSHIFT,
        "BOOLAND": OP_BOOLAND,
        "BOOLOR": OP_BOOLOR,
        "NUMEQUAL": OP_NUMEQUAL,
        "NUMEQUALVERIFY": OP_NUMEQUALVERIFY,
        "NUMNOTEQUAL": OP_NUMNOTEQUAL,
        "LESSTHAN": OP_LESSTHAN,
        "GREATERTHAN": OP_GREATERTHAN,
        "LESSTHANOREQUAL": OP_LESSTHANOREQUAL,
        "GREATERTHANOREQUAL": OP_GREATERTHANOREQUAL,
        "MIN": OP_MIN,
        "MAX": OP_MAX,
        "WITHIN": OP_WITHIN,
        "RIPEMD160": OP_RIPEMD160,
        "SHA1": OP_SHA1,
        "SHA256": OP_SHA256,
        "HASH160": OP_HASH160,
        "HASH256": OP_HASH256,
        "CODESEPARATOR": OP_CODESEPARATOR,
        "CHECKSIG": OP_CHECKSIG,
        "CHECKSIGVERIFY": OP_CHECKSIGVERIFY,
        "CHECKMULTISIG": OP_CHECKMULTISIG,
        "CHECKMULTISIGVERIFY": OP_CHECKMULTISIGVERIFY,
        "NOP1": OP_NOP1,
        "CHECKLOCKTIMEVERIFY": OP_CHECKLOCKTIMEVERIFY,
        "NOP2": OP_NOP2,
        "NOP3": OP_NOP3,
        "NOP4": OP_NOP4,
        "NOP5": OP_NOP5,
        "NOP6": OP_NOP6,
        "NOP7": OP_NOP7,
        "NOP8": OP_NOP8,
        "NOP9": OP_NOP9,
        "NOP10": OP_NOP10
    ]
    
    public static func getOpCodeName(opcode: Int) -> String {
        if var opCodeName = opCodeMap[opcode] {
            return opCodeName
        }
        return "NON_OP(\(opcode))"
    }

    public static func getPushDataName(opcode: Int) -> String {
        if var opCodeName = opCodeMap[opcode] {
            return opCodeName
        }
        return "PUSHDATA(\(opcode))"
    }

    public static func getOpCode(opCodeName: String) -> Int {
        if var opCode = opCodeNameMap[opCodeName] {
            return opCode
        }
        return OP_INVALIDOPCODE
    }
}
