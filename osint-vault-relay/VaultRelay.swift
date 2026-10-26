import Foundation

enum VaultRelay {
    private static let queue = DispatchQueue(label: "osint-vault-relay")
    private static var retryTimer: Timer?
    private static var script: URL {
        Bundle.main.resourceURL!.appendingPathComponent("vault_relay.py")
    }

    static func start(onStatus: @escaping (String) -> Void) {
        submit("flush", onStatus: onStatus)
        retryTimer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { _ in submit("flush", onStatus: onStatus) }
    }

    static func submit(_ operation: String, data: Data? = nil, onStatus: @escaping (String) -> Void) {
        queue.async {
            let process = Process(), input = Pipe(), output = Pipe()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            var environment = ProcessInfo.processInfo.environment
            environment["PATH"] = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
            process.environment = environment
            process.arguments = ["python3", script.path, operation]
            process.standardInput = input
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
                if let data { try input.fileHandleForWriting.write(contentsOf: data) }
                try input.fileHandleForWriting.close()
                let response = output.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                let object = (try? JSONSerialization.jsonObject(with: response)) as? [String: Any] ?? [:]
                let pending = object["pending"].map { String(describing: $0) } ?? "unknown"
                let sent = object["sent"].map { String(describing: $0) } ?? "0"
                let error = object["error"] as? String
                let message = "Vault · \(sent) sent · \(pending) pending" + (error.map { " · \($0)" } ?? "")
                DispatchQueue.main.async { onStatus(message) }
            } catch { DispatchQueue.main.async { onStatus("Vault · relay unavailable; findings remain local") } }
        }
    }
}
