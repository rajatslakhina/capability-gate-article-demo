// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "CapabilityGate",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "CapabilityGate", targets: ["CapabilityGate"])
    ],
    targets: [
        .target(name: "CapabilityGate"),
        .testTarget(name: "CapabilityGateTests", dependencies: ["CapabilityGate"])
    ]
)
