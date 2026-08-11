// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "se-sshctl",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "SSHCTLCore", targets: ["SSHCTLCore"]),
        .executable(name: "se-sshctl", targets: ["se-sshctl"]),
    ],
    targets: [
        .target(name: "SSHCTLCore"),
        .executableTarget(name: "se-sshctl", dependencies: ["SSHCTLCore"]),
        .testTarget(
            name: "SSHCTLCoreTests",
            dependencies: ["SSHCTLCore"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
