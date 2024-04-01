// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "PSBTSwift",
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "PSBTSwift",
            targets: ["PSBTSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.4.1"),
        .package(name: "Secp256k1Swift", url: "https://github.com/mathwallet/Secp256k1Swift", from: "2.0.0"),
        .package(url: "https://github.com/yuzhiyou1990/BitcoinSwift.git", from: "1.0.1"),
        .package(url: "https://github.com/mw99/DataCompression", from: "3.4.1"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.62.0"),
        .package(url: "https://github.com/xueyuejie/ASN1.git", branch: "master")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "PSBTSwift",
            dependencies: ["CryptoSwift", "Secp256k1Swift", "BitcoinSwift", "DataCompression",.product(name: "NIOCore", package: "swift-nio"), "ASN1"]
        ),
        .testTarget(
            name: "PSBTSwiftTests",
            dependencies: ["PSBTSwift"]),
    ]
)
