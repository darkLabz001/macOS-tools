import Foundation
import Darwin

let args = CommandLine.arguments
if let index = args.firstIndex(of: "-oA") {
    if ProcessInfo.processInfo.environment["MAPPER_FIXTURE_HOLD"] == "1" {
        while true { Thread.sleep(forTimeInterval: 0.1) }
    }
    let prefix = args[index + 1]
    let xml = "<nmaprun><host><status state='up'/><address addr='127.0.0.1' addrtype='ipv4'/><ports><port protocol='tcp' portid='4444'><state state='open'/><service name='fixture' product='Synthetic service'/></port></ports></host></nmaprun>"
    try xml.write(toFile: prefix + ".xml", atomically: true, encoding: .utf8)
    for ext in ["nmap", "gnmap"] { try "Synthetic scan fixture\n".write(toFile: prefix + "." + ext, atomically: true, encoding: .utf8) }
    print("Synthetic service 127.0.0.1:4444 open")
    exit(0)
}
let fm = FileManager.default
let root = fm.temporaryDirectory.appendingPathComponent("mapper-worker-fixture-\(UUID().uuidString)", isDirectory: true)
try fm.createDirectory(at: root, withIntermediateDirectories: true)
defer { try? fm.removeItem(at: root) }
let executable = URL(fileURLWithPath: args[0])
func job(_ name: String) throws -> URL {
    let dir = root.appendingPathComponent(name, isDirectory: true)
    try fm.createDirectory(at: dir, withIntermediateDirectories: true)
    var c = ScanConfig(); c.targets = "127.0.0.1"; c.ports = "4444"; c.skipDiscovery = true
    try writeJSON(c, dir.appendingPathComponent("config.json"))
    return dir
}
let complete = try job("complete")
precondition(worker(complete, nmapExecutable: executable) == 0)
let saved = try JSONDecoder().decode(Snapshot.self, from: Data(contentsOf: complete.appendingPathComponent("snapshot.json")))
precondition(saved.hosts.count == 1 && saved.hosts[0].ports[0].state == "open")
for name in ["scan.xml", "scan.nmap", "scan.gnmap", "snapshot.json", "status.json", "console.log"] { precondition(fm.fileExists(atPath: complete.appendingPathComponent(name).path)) }
let cancelled = try job("cancelled")
setenv("MAPPER_FIXTURE_HOLD", "1", 1)
DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { try! Data().write(to: cancelled.appendingPathComponent("STOP")) }
_ = worker(cancelled, nmapExecutable: executable)
unsetenv("MAPPER_FIXTURE_HOLD")
let status = try JSONDecoder().decode(WorkerStatus.self, from: Data(contentsOf: cancelled.appendingPathComponent("status.json")))
precondition(status.stopped && !fm.fileExists(atPath: cancelled.appendingPathComponent("snapshot.json").path))
let neverStarted = try job("never-started")
try Data().write(to: neverStarted.appendingPathComponent("STOP"))
precondition(worker(neverStarted, nmapExecutable: executable) == 143)
precondition(!fm.fileExists(atPath: neverStarted.appendingPathComponent("STARTED").path))
let failure = try job("failure")
precondition(worker(failure, nmapExecutable: URL(fileURLWithPath: "/not/a/real/nmap")) == 1)
print("PASS: worker output artifacts, snapshot parsing, running-process cancellation, pre-start cancellation, and launch failure")
