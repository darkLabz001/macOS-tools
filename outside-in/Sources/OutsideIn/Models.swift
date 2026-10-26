import Foundation

enum AssetKind: String, Codable, CaseIterable {
    case domain, address, nameserver, mailserver, repository, document
    var icon: String {
        switch self {
        case .domain: return "globe"
        case .address: return "network"
        case .nameserver: return "server.rack"
        case .mailserver: return "envelope"
        case .repository: return "chevron.left.forwardslash.chevron.right"
        case .document: return "doc.text"
        }
    }
}

struct Asset: Identifiable, Codable, Equatable {
    var id = UUID()
    var value: String
    var kind: AssetKind
}

enum EvidenceStatus: String, Codable, CaseIterable {
    case observed = "Observed", hypothesis = "Hypothesis"
}

struct Evidence: Identifiable, Codable {
    var id = UUID()
    var from: UUID
    var to: UUID
    var relationship: String
    var source: String
    var excerpt: String
    var status: EvidenceStatus
    var capturedAt = Date()
}

struct CollectionRun: Identifiable, Codable {
    var id = UUID()
    var domain: String
    var recordType: String
    var capturedAt = Date()
    var outcome: String
    var rawResponse: String
}

struct Investigation: Identifiable, Codable {
    var id = UUID()
    var name: String
    var scope: String
    var isDemo = false
    var createdAt = Date()
    var assets: [Asset] = []
    var evidence: [Evidence] = []
    var runs: [CollectionRun] = []

    mutating func addAsset(_ value: String, kind: AssetKind) -> UUID {
        let clean = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if let existing = assets.first(where: { $0.value.lowercased() == clean.lowercased() && $0.kind == kind }) {
            return existing.id
        }
        let asset = Asset(value: clean, kind: kind)
        assets.append(asset)
        return asset.id
    }

    func containsDomain(_ name: String) -> Bool {
        guard TargetInput.ip(scope) == nil else { return false }
        let normalized = name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return normalized == scope || normalized.hasSuffix("." + scope)
    }

    func allowsScan(_ target: String) -> Bool {
        if let address = TargetInput.ip(target) {
            return address == scope || assets.contains { $0.kind == .address && TargetInput.ip($0.value) == address }
        }
        return containsDomain(target)
    }

    func label(_ id: UUID) -> String { assets.first(where: { $0.id == id })?.value ?? "Unknown asset" }

    var leads: [Lead] {
        var result: [Lead] = []
        let domains = assets.filter { $0.kind == .domain && containsDomain($0.value) }
        for domain in domains {
            let completed = Set(runs.filter { $0.domain == domain.value && $0.outcome.hasPrefix("Success") }.map(\.recordType))
            let missing = DNSCollector.recordTypes.filter { !completed.contains($0) }
            if !missing.isEmpty {
                result.append(Lead(id: "dns-\(domain.id)", title: "Establish the DNS baseline", detail: "\(domain.value) has no successful collection for \(missing.joined(separator: ", ")). Collect records before inferring infrastructure relationships.", assetID: domain.id, action: .collect))
            }
        }
        if let root = assets.first(where: { $0.value == scope }) {
            let completed = Set(runs.filter { $0.domain == scope && $0.outcome.hasPrefix("Success") }.map(\.recordType))
            let missing = ScannerModule.defaults(for: scope).filter { $0 != .dns && !completed.contains($0.rawValue) }.sorted { $0.rawValue < $1.rawValue }
            if !missing.isEmpty {
                result.append(Lead(id: "enrich-\(root.id)", title: "Expand the target profile", detail: "\(scope) is missing successful collections for: \(missing.map(\.title).joined(separator: ", ")). Open Scanners to choose the next modules.", assetID: root.id, action: .scan))
            }
        }
        for item in evidence where item.status == .hypothesis {
            result.append(Lead(id: item.id.uuidString, title: "Corroborate a possible connection", detail: "\(label(item.from)) → \(label(item.to)): \(item.relationship). Find an independent source before treating this as fact.", assetID: item.to, action: .inspect))
        }
        let external = assets.filter { [.nameserver, .mailserver].contains($0.kind) && !containsDomain($0.value) }
        if let first = external.first {
            result.append(Lead(id: "providers", title: "Separate providers from owned assets", detail: "\(external.count) external service host(s) appear in this case. A DNS relationship demonstrates service use, not ownership or authorization to test a provider.", assetID: first.id, action: .inspect))
        }
        if evidence.isEmpty {
            result.append(Lead(id: "source", title: "Bring in a public-source clue", detail: "Add a repository reference, document, or hostname with a source URL and exact excerpt. The graph will preserve the connection and its provenance.", assetID: nil, action: .add))
        }
        return result
    }

    static func demo() -> Investigation {
        var item = Investigation(name: "Northstar · training case", scope: "northstar.example", isDemo: true)
        let root = item.addAsset("northstar.example", kind: .domain)
        let staging = item.addAsset("staging.northstar.example", kind: .domain)
        let repo = item.addAsset("github.example/northstar/web", kind: .repository)
        let address = item.addAsset("192.0.2.24", kind: .address)
        let mail = item.addAsset("mx.provider.example", kind: .mailserver)
        let doc = item.addAsset("Launch notes · 2023", kind: .document)
        func link(_ from: UUID, _ to: UUID, _ relation: String, _ excerpt: String, _ status: EvidenceStatus = .observed) -> Evidence {
            Evidence(from: from, to: to, relationship: relation, source: "https://northstar.example/training-fixture", excerpt: excerpt, status: status)
        }
        item.evidence = [
            link(root, repo, "references repository", "Synthetic fixture: company page links to the web repository."),
            link(repo, staging, "mentions hostname", "Synthetic fixture: DEPLOY_HOST=staging.northstar.example"),
            link(staging, address, "A record", "Synthetic fixture: staging.northstar.example A 192.0.2.24"),
            link(root, mail, "MX record", "Synthetic fixture: 10 mx.provider.example"),
            link(root, doc, "published document", "Synthetic fixture: archived launch notes."),
            link(doc, staging, "may describe retired environment", "Synthetic fixture: launch notes mention a legacy preview environment.", .hypothesis)
        ]
        return item
    }
}

struct Lead: Identifiable {
    enum Action { case collect, inspect, add, scan }
    var id: String
    var title: String
    var detail: String
    var assetID: UUID?
    var action: Action
}

enum DomainInput {
    static func normalize(_ input: String) -> String? {
        var value = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if value.hasPrefix("https://") || value.hasPrefix("http://") {
            guard let components = URLComponents(string: value), let host = components.host,
                  components.user == nil, components.password == nil else { return nil }
            value = host
        }
        value = value.trimmingCharacters(in: CharacterSet(charactersIn: "."))
        guard value.count <= 253, value.contains("."), !value.contains(":"),
              !value.allSatisfy({ $0.isNumber || $0 == "." }) else { return nil }
        let labels = value.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.allSatisfy({ label in
            !label.isEmpty && label.count <= 63 && label.first != "-" && label.last != "-" &&
            label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }) else { return nil }
        return value
    }
}

enum Reports {
    static func markdown(_ item: Investigation) -> String {
        func inline(_ text: String) -> String { text.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ") }
        var lines = ["# \(inline(item.name))", "", "Scope: \(item.scope)", "Exported: \(Date().ISO8601Format())", ""]
        if item.isDemo { lines += ["TRAINING CASE — all findings are synthetic fixtures.", ""] }
        lines += ["## Assets", ""]
        lines += item.assets.map { "- [\($0.kind.rawValue)] \(inline($0.value))" }
        lines += ["", "## Evidence", ""]
        for evidence in item.evidence {
            lines += ["### \(inline(item.label(evidence.from))) → \(inline(item.label(evidence.to)))", "", "- Status: \(evidence.status.rawValue)", "- Relationship: \(inline(evidence.relationship))", "- Source: \(inline(evidence.source))", "- Captured: \(evidence.capturedAt.ISO8601Format())", "", "> \(inline(evidence.excerpt))", ""]
        }
        lines += ["## Investigation gaps", ""]
        lines += item.leads.map { "- \($0.title): \(inline($0.detail))" }
        lines += ["", "## Collection log", ""]
        lines += item.runs.map { "- \($0.capturedAt.ISO8601Format()) · \($0.domain) · \($0.recordType) · \(inline($0.outcome))" }
        return lines.joined(separator: "\n")
    }
}
