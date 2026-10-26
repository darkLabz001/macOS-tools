// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OutsideIn",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "OutsideIn", targets: ["OutsideIn"])],
    targets: [
        .executableTarget(name: "OutsideIn")
    ]
)
