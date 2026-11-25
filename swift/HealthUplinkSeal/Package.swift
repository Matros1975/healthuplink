// swift-tools-version: 6.0
import PackageDescription

/// The iPhone's sealing, signing, wire-encoding and TLS pin code, kept apart so the published source is the
/// shipped source. Static library: the app embeds no Frameworks/ folder.
let package = Package(
    name: "HealthUplinkSeal",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "HealthUplinkSeal", type: .static, targets: ["HealthUplinkSeal"]),
    ],
    targets: [
        .target(
            name: "HealthUplinkSeal",
            linkerSettings: [.linkedLibrary("z")]
        ),
        .testTarget(
            name: "HealthUplinkSealTests",
            dependencies: ["HealthUplinkSeal"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
