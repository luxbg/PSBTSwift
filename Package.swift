// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "PSBTSwift",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "PSBTSwift",
            targets: ["PSBTSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.4.1"),
        .package(name: "Secp256k1Swift", url: "https://github.com/mathwallet/Secp256k1Swift", from: "2.0.0"),
        .package(name: "Bech32", url: "https://github.com/lishuailibertine/Bech32", from: "1.0.5"),
        .package(url: "https://github.com/mw99/DataCompression", from: "3.4.1"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.0.0"),
        .package(url: "https://github.com/mathwallet/Base58Swift.git", from: "0.0.1"),
        .package(url: "https://github.com/xueyuejie/ASN1.git", from: "2.5.2")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "PSBTSwift",
            dependencies: ["CryptoSwift",
                           "Secp256k1Swift",
                           "Bech32",
                           "DataCompression",
                           .product(name: "NIOCore", package: "swift-nio"),
                           .product(name: "BIP32Swift", package: "Secp256k1Swift"),
                           "Base58Swift",
                           "ASN1",
                           "PSBTCryptoKit"]
        ),
        .target(name: "PSBTCryptoKit"),
        .testTarget(
            name: "PSBTSwiftTests",
            dependencies: ["PSBTSwift"]),
    ]
)
