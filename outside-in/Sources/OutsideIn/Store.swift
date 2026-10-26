import SwiftUI
import AppKit

@MainActor final class CaseStore: ObservableObject {
    @Published var cases: [Investigation] = []
    @Published var selection: UUID?
    @Published var selectedAsset: UUID?
    @Published var isCollecting = false
    @Published var scanStatus = "Choose a target and collection modules."
    @Published var scanCompleted = 0
    @Published var scanTotal = 0
    @Published var notice: String?
    @Published var vaultStatus = "Vault: starting"
    @Published var isSyncing = false
    private var outbox = VaultOutbox()
    private var outboxFailed = false
    private let outboxURL = VaultConfiguration.directory.appendingPathComponent("vault-outbox.json")
    private var loadFailed = false
    let fileURL: URL

    init() {
        let directory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("macOS-tools/OutsideIn", isDirectory: true)
        fileURL = directory.appendingPathComponent("cases.json")
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            if FileManager.default.fileExists(atPath: fileURL.path) {
                let data = try Data(contentsOf: fileURL)
                cases = try JSONDecoder().decode([Investigation].self, from: data)
            } else {
                cases = [.demo()]
            }
        } catch {
            loadFailed = true
            notice = "Could not read saved cases. Existing data will not be overwritten. \(error.localizedDescription)"
        }
        selection = cases.first?.id
        do {
            if FileManager.default.fileExists(atPath: outboxURL.path) {
                outbox = try JSONDecoder().decode(VaultOutbox.self, from: Data(contentsOf: outboxURL))
            }
        } catch { outboxFailed = true; vaultStatus = "Vault: cannot read retry queue" }
        Task { [weak self] in
            while !Task.isCancelled {
                await self?.syncVault()
                try? await Task.sleep(for: .seconds(60))
            }
        }
    }

    var current: Investigation? { cases.first { $0.id == selection } }

    func save() {
        guard !loadFailed else { return }
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(cases).write(to: fileURL, options: .atomic)
        } catch { notice = "Save failed: \(error.localizedDescription)" }
    }

    func create(name: String, scope: String) {
        guard let domain = TargetInput.normalize(scope) else { notice = "Enter a valid domain or IPv4/IPv6 address."; return }
        var item = Investigation(name: name.isEmpty ? domain : name, scope: domain)
        _ = item.addAsset(domain, kind: TargetInput.ip(domain) == nil ? .domain : .address)
        cases.append(item)
        selection = item.id
        selectedAsset = nil
        save()
        Task { await syncVault() }
    }

    func addEvidence(value: String, kind: AssetKind, from: UUID, relation: String, source: String, excerpt: String, status: EvidenceStatus) {
        guard let index = cases.firstIndex(where: { $0.id == selection }) else { return }
        let target = cases[index].addAsset(value, kind: kind)
        cases[index].evidence.append(Evidence(from: from, to: target, relationship: relation, source: source, excerpt: excerpt, status: status))
        selectedAsset = target
        save()
        Task { await syncVault() }
    }

    func collect(domain: String) async {
        guard !isCollecting, let current, !current.isDemo, current.containsDomain(domain), DomainInput.normalize(domain) != nil else {
            notice = "Choose a domain inside the case scope. The training case uses synthetic data."
            return
        }
        let caseID = current.id
        isCollecting = true
        defer { isCollecting = false }
        let results = await DNSCollector.collect(domain: domain)
        guard let index = cases.firstIndex(where: { $0.id == caseID }) else { return }
        DNSCollector.apply(results, domain: domain, to: &cases[index])
        save()
        await syncVault()
        let failures = results.filter { $0.error != nil || $0.response?.Status != 0 }.count
        notice = (failures == 0 ? "DNS collection complete. Evidence and raw responses saved." : "Collection finished with \(failures) unsuccessful queries. See the collection log.") + "\n\(vaultStatus)"
    }

    func syncVault() async {
        guard !isSyncing, !outboxFailed, !loadFailed else { return }
        isSyncing = true
        defer { isSyncing = false }
        do {
            try outbox.enqueue(cases)
            try persistOutbox()
            let configuration = try VaultConfiguration.load()
            if outbox.pending.isEmpty {
                vaultStatus = "Vault: up to date"
                return
            }
            let entries = outbox.pending.sorted { $0.key < $1.key }
            for (identity, entry) in entries {
                vaultStatus = "Vault: sending · \(outbox.pending.count) pending"
                try await VaultTransport.send(entry, configuration: configuration)
                outbox.acknowledge(identity, fingerprint: entry.fingerprint)
                try persistOutbox()
            }
            vaultStatus = "Vault: synced · \(outbox.delivered.count) records"
        } catch {
            vaultStatus = "Vault: \(outbox.pending.count) pending · \(error.localizedDescription)"
        }
    }

    private enum ScanOutput { case dns([DNSResult]), other(ScannerResult) }

    func scan(target input: String, modules: Set<ScannerModule>) async {
        guard !isCollecting, let current, !current.isDemo,
              let target = TargetInput.normalize(input), current.allowsScan(target) else {
            notice = "Use the case domain, one of its subdomains, or an IP already in this case. Create an IP case for a different address."
            return
        }
        let chosen = modules.filter { $0.supports(target) }
        guard !chosen.isEmpty else { return }
        let caseID = current.id
        isCollecting = true
        scanCompleted = 0; scanTotal = chosen.count
        scanStatus = "Scanning \(target)…"
        defer { isCollecting = false }
        var failures = 0
        await withTaskGroup(of: ScanOutput.self) { group in
            for module in chosen {
                group.addTask {
                    if module == .dns { return .dns(await DNSCollector.collect(domain: target)) }
                    return .other(await ReconScanner.collect(module, target: target))
                }
            }
            for await output in group {
                guard let index = cases.firstIndex(where: { $0.id == caseID }) else { continue }
                let name: String
                switch output {
                case .dns(let results):
                    DNSCollector.apply(results, domain: target, to: &cases[index])
                    if results.contains(where: { $0.error != nil || $0.response?.Status != 0 }) { failures += 1 }
                    name = "DNS"
                case .other(let result):
                    ReconScanner.apply(result, to: &cases[index])
                    if result.error != nil { failures += 1 }
                    name = result.module.rawValue
                }
                scanCompleted += 1
                scanStatus = "\(target) · \(scanCompleted)/\(scanTotal) modules finished · latest: \(name)"
                save()
            }
        }
        scanStatus = "Finished \(target) · \(scanTotal - failures)/\(scanTotal) modules succeeded. See Collection log for results."
        await syncVault()
    }

    private func persistOutbox() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        try encoder.encode(outbox).write(to: outboxURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: outboxURL.path)
    }

    func export(json: Bool) {
        guard let current else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "outside-in-\(current.scope).\(json ? "json" : "md")"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let data: Data
            if json {
                let encoder = JSONEncoder()
                encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                data = try encoder.encode(current)
            } else { data = Data(Reports.markdown(current).utf8) }
            try data.write(to: url, options: .atomic)
        } catch { notice = "Export failed: \(error.localizedDescription)" }
    }
}
