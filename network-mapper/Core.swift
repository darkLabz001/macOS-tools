import Foundation
import Darwin

struct ScanConfig: Codable {
    var targets = ""
    var profile = "TCP connect"
    var ports = ""
    var topPorts = 100
    var timing = 3
    var versions = false
    var os = false
    var aggressive = false
    var skipDiscovery = false
    var traceroute = false
    var ipv6 = false
    var scripts = "None"
    var scriptArgs = ""
    var excludes = ""
    var maxRate = ""
    var hostTimeout = "120"
    var fragment = false
    var decoys = ""
    var sourcePort = ""
    var spoofMAC = ""
    var networkInterface = ""

    static let profiles = ["Discovery only", "TCP connect", "TCP SYN", "UDP", "ACK firewall mapping", "NULL", "FIN", "Xmas"]
    static let scriptChoices = ["None", "default", "safe", "discovery", "vuln", "auth", "intrusive", "brute", "exploit"]
    var needsRoot: Bool {
        !["TCP connect", "Discovery only"].contains(profile) || os || aggressive || traceroute || fragment || !decoys.isEmpty || !spoofMAC.isEmpty || !sourcePort.isEmpty
    }
    var targetTokens: [String] { targets.split(whereSeparator: { $0.isWhitespace }).map(String.init) }
    func validToken(_ value: String) -> Bool {
        !value.isEmpty && !value.hasPrefix("-") && value.range(of: "^[A-Za-z0-9._:/,%\\-]+$", options: .regularExpression) != nil
    }
    func validate() throws {
        guard !targetTokens.isEmpty, targetTokens.allSatisfy(validToken) else { throw MapperError.message("Enter explicit hostnames, IPs, or CIDRs separated by spaces. Option flags and shell punctuation are not targets.") }
        guard Self.profiles.contains(profile), Self.scriptChoices.contains(scripts), (0...5).contains(timing), (1...65535).contains(topPorts) else { throw MapperError.message("Invalid scan profile, scripts, timing, or top-port count.") }
        if !ports.isEmpty {
            guard ports.range(of: "^[0-9,\\-]+$", options: .regularExpression) != nil else { throw MapperError.message("Ports must be numbers/ranges such as 22,80,443 or 1-65535.") }
            for range in ports.split(separator: ",", omittingEmptySubsequences: false) {
                let parts = range.split(separator: "-", omittingEmptySubsequences: false)
                let numbers = parts.compactMap { Int($0) }
                guard (1...2).contains(parts.count), numbers.count == parts.count, numbers.allSatisfy({ (1...65535).contains($0) }), numbers.first! <= numbers.last! else { throw MapperError.message("Invalid port range.") }
            }
        }
        if !excludes.isEmpty && !excludes.split(separator: ",").allSatisfy({ validToken(String($0)) }) { throw MapperError.message("Exclusions must be comma-separated hosts or networks.") }
        for (value, label) in [(maxRate, "Max rate"), (hostTimeout, "Host timeout")] {
            if !value.isEmpty && (Int(value) == nil || Int(value)! < 1) { throw MapperError.message("\(label) must be a positive integer.") }
        }
        if !sourcePort.isEmpty && (Int(sourcePort) == nil || !(1...65535).contains(Int(sourcePort)!)) { throw MapperError.message("Source port must be 1–65535.") }
        for (value, label) in [(decoys, "Decoys"), (spoofMAC, "MAC address"), (networkInterface, "Interface")] {
            if !value.isEmpty && !validToken(value) { throw MapperError.message("Invalid \(label) value.") }
        }
        if profile == "TCP connect" && (fragment || !decoys.isEmpty || !spoofMAC.isEmpty || !sourcePort.isEmpty) { throw MapperError.message("Choose a raw scan type such as TCP SYN for fragmentation, decoys, MAC spoofing, or source-port control.") }
        if profile == "Discovery only" && (aggressive || os || versions || scripts != "None") { throw MapperError.message("Discovery only cannot include port scripts, service detection, OS detection, or -A. Choose a port scan profile.") }
        if profile == "Discovery only" && skipDiscovery { throw MapperError.message("Turn off Skip discovery for a discovery-only scan.") }
    }
    func arguments(output: String) throws -> [String] {
        try validate()
        let types = ["Discovery only": "-sn", "TCP connect": "-sT", "TCP SYN": "-sS", "UDP": "-sU", "ACK firewall mapping": "-sA", "NULL": "-sN", "FIN": "-sF", "Xmas": "-sX"]
        var a = [types[profile]!, "-n", "-T\(timing)", "--reason", "-v", "--stats-every", "2s", "-oA", output]
        if profile != "Discovery only" { a += ports.isEmpty ? ["--top-ports", String(topPorts)] : ["-p", ports] }
        if aggressive { a += ["-A"] }
        else {
            if versions { a += ["-sV"] }
            if os { a += ["-O"] }
            if traceroute { a += ["--traceroute"] }
        }
        if skipDiscovery { a += ["-Pn"] }
        if ipv6 { a += ["-6"] }
        if scripts != "None" { a += ["--script", scripts] }
        if !scriptArgs.isEmpty && scripts != "None" { a += ["--script-args", scriptArgs] }
        if !excludes.isEmpty { a += ["--exclude", excludes] }
        if !maxRate.isEmpty { a += ["--max-rate", maxRate] }
        if !hostTimeout.isEmpty { a += ["--host-timeout", hostTimeout + "s"] }
        if fragment { a += ["-f"] }
        if !decoys.isEmpty { a += ["-D", decoys] }
        if !sourcePort.isEmpty { a += ["--source-port", sourcePort] }
        if !spoofMAC.isEmpty { a += ["--spoof-mac", spoofMAC] }
        if !networkInterface.isEmpty { a += ["-e", networkInterface] }
        return a + targetTokens
    }
}

enum MapperError: LocalizedError {
    case message(String)
    var errorDescription: String? { if case let .message(text) = self { return text }; return nil }
}

struct Port: Codable, Equatable {
    var number: String
    var proto: String
    var state = "unknown"
    var service = ""
    var version = ""
    var scripts: [String] = []
    var key: String { "\(number)/\(proto)" }
}
struct Host: Codable, Equatable {
    var address = ""
    var name = ""
    var state = "unknown"
    var os = ""
    var ports: [Port] = []
    var scripts: [String] = []
}
struct Snapshot: Codable {
    var date: Date
    var config: ScanConfig
    var hosts: [Host]
}
struct WorkerStatus: Codable {
    var exitCode: Int32
    var stopped: Bool
    var error: String?
}

final class NmapXML: NSObject, XMLParserDelegate {
    var hosts: [Host] = []
    var host: Host?
    var port: Port?
    var parseError: String?
    static func read(_ data: Data) throws -> [Host] {
        let delegate = NmapXML(), parser = XMLParser(data: data)
        parser.shouldResolveExternalEntities = false
        parser.delegate = delegate
        guard parser.parse() else { throw MapperError.message("Invalid/incomplete Nmap XML: \(parser.parserError?.localizedDescription ?? "unknown error")") }
        return delegate.hosts
    }
    func parser(_ parser: XMLParser, didStartElement name: String, namespaceURI: String?, qualifiedName: String?, attributes a: [String: String]) {
        switch name {
        case "host": host = Host()
        case "status": host?.state = a["state"] ?? "unknown"
        case "address": if host?.address.isEmpty == true || a["addrtype"] == "ipv4" || a["addrtype"] == "ipv6" { if a["addrtype"] != "mac" { host?.address = a["addr"] ?? "" } }
        case "hostname": if host?.name.isEmpty == true { host?.name = a["name"] ?? "" }
        case "osmatch": if host?.os.isEmpty == true { host?.os = a["name"] ?? "" }
        case "port": port = Port(number: a["portid"] ?? "", proto: a["protocol"] ?? "")
        case "state": port?.state = a["state"] ?? "unknown"
        case "service":
            port?.service = a["name"] ?? ""
            port?.version = [a["product"], a["version"], a["extrainfo"]].compactMap { $0 }.joined(separator: " ")
        case "script":
            let text = "\(a["id"] ?? "script"): \(a["output"] ?? "")"
            if port != nil { port?.scripts.append(text) } else { host?.scripts.append(text) }
        default: break
        }
    }
    func parser(_ parser: XMLParser, didEndElement name: String, namespaceURI: String?, qualifiedName: String?) {
        if name == "port", let port { host?.ports.append(port); self.port = nil }
        if name == "host", let host { if !host.address.isEmpty { hosts.append(host) }; self.host = nil }
    }
}

func compare(_ baseline: [Host], _ current: [Host]) -> String {
    let old = Dictionary(baseline.map { ($0.address, $0) }, uniquingKeysWith: { first, _ in first })
    let new = Dictionary(current.map { ($0.address, $0) }, uniquingKeysWith: { first, _ in first })
    var lines: [String] = []
    for address in Set(old.keys).union(new.keys).sorted() {
        guard let before = old[address] else { lines.append("+ HOST \(address)"); continue }
        guard let after = new[address] else { lines.append("− HOST \(address)"); continue }
        if before.state != after.state { lines.append("~ HOST \(address): \(before.state) → \(after.state)") }
        if before.os != after.os { lines.append("~ OS \(address): \(before.os) → \(after.os)") }
        let a = Dictionary(before.ports.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
        let b = Dictionary(after.ports.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
        for key in Set(a.keys).union(b.keys).sorted() {
            if a[key] == nil { lines.append("+ PORT \(address) \(key) \(b[key]!.state) \(b[key]!.service)") }
            else if b[key] == nil { lines.append("− PORT \(address) \(key) (absent from this scan)") }
            else if a[key] != b[key] { lines.append("~ PORT \(address) \(key): \(a[key]!.state) \(a[key]!.service) \(a[key]!.version) → \(b[key]!.state) \(b[key]!.service) \(b[key]!.version)") }
        }
        if before.scripts != after.scripts { lines.append("~ HOST SCRIPT OUTPUT \(address)") }
    }
    return lines.isEmpty ? "No differences in the recorded hosts, ports, services, or script output." : lines.joined(separator: "\n")
}

func shellQuote(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "'\"'\"'") + "'" }
func writeJSON<T: Encodable>(_ value: T, _ url: URL) throws {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    try encoder.encode(value).write(to: url)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
}

func worker(_ directory: URL, nmapExecutable: URL = URL(fileURLWithPath: "/opt/homebrew/bin/nmap")) -> Int32 {
    let fm = FileManager.default
    let stop = directory.appendingPathComponent("STOP")
    let status = directory.appendingPathComponent("status.json")
    do {
        let config = try JSONDecoder().decode(ScanConfig.self, from: Data(contentsOf: directory.appendingPathComponent("config.json")))
        let args = try config.arguments(output: directory.appendingPathComponent("scan").path)
        if fm.fileExists(atPath: stop.path) { try writeJSON(WorkerStatus(exitCode: 143, stopped: true), status); return 143 }
        if config.needsRoot && getuid() != 0 { throw MapperError.message("This profile requires sudo. Start it from Network Mapper to open the authorization Terminal.") }
        try Data().write(to: directory.appendingPathComponent("STARTED"))
        let log = directory.appendingPathComponent("console.log")
        fm.createFile(atPath: log.path, contents: nil, attributes: [.posixPermissions: 0o644])
        let handle = try FileHandle(forWritingTo: log)
        defer { try? handle.close() }
        let p = Process()
        p.executableURL = nmapExecutable
        p.arguments = args
        p.standardOutput = handle; p.standardError = handle; p.standardInput = FileHandle.nullDevice
        try p.run()
        var cancelled = false
        while p.isRunning {
            if fm.fileExists(atPath: stop.path) {
                cancelled = true; p.terminate()
                let deadline = Date().addingTimeInterval(2)
                while p.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
                if p.isRunning { Darwin.kill(p.processIdentifier, SIGKILL) }
                break
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
        p.waitUntilExit()
        if p.terminationStatus == 0 && !cancelled {
            let hosts = try NmapXML.read(Data(contentsOf: directory.appendingPathComponent("scan.xml")))
            try writeJSON(Snapshot(date: Date(), config: config, hosts: hosts), directory.appendingPathComponent("snapshot.json"))
        }
        try writeJSON(WorkerStatus(exitCode: p.terminationStatus, stopped: cancelled), status)
        return p.terminationStatus
    } catch {
        try? writeJSON(WorkerStatus(exitCode: 1, stopped: false, error: error.localizedDescription), status)
        return 1
    }
}
