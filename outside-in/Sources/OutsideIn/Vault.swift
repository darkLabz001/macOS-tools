import Foundation
import CryptoKit

struct VaultRecord: Codable {
    var source = "outside-in"
    var type: String
    var value: String
    var tags: [String]
    var metadata: Metadata

    struct Metadata: Codable {
        var case_id: UUID
        var case_name: String
        var scope: String
        var asset_id: UUID
        var asset_kind: String
        var resolves_to: [String]
        var evidence: [SourceEvidence]
        var collections: [CollectionRun]
    }
    struct SourceEvidence: Codable {
        var id: UUID
        var from: String
        var to: String
        var relationship: String
        var source_url: String
        var excerpt: String
        var status: String
        var captured_at: Date
    }

    static func records(for item: Investigation) -> [VaultRecord] {
        guard !item.isDemo else { return [] }
        return item.assets.map { asset in
            let related = item.evidence.filter { $0.from == asset.id || $0.to == asset.id }
            let type: String
            switch asset.kind {
            case .address: type = "ip"
            case .domain: type = asset.value != item.scope && item.containsDomain(asset.value) ? "subdomain" : "domain"
            case .nameserver, .mailserver: type = "domain"
            case .repository: type = "url"
            case .document: type = "document"
            }
            let addresses = item.evidence.filter { $0.from == asset.id && ["A record", "AAAA record"].contains($0.relationship) }.map { item.label($0.to) }
            let sources = related.map { SourceEvidence(id: $0.id, from: item.label($0.from), to: item.label($0.to), relationship: $0.relationship, source_url: $0.source, excerpt: $0.excerpt, status: $0.status.rawValue, captured_at: $0.capturedAt) }
            return VaultRecord(type: type, value: asset.value,
                tags: ["osint", "outside-in", asset.kind.rawValue] + (related.contains { $0.relationship.hasSuffix("record") } ? ["dns"] : []),
                metadata: Metadata(case_id: item.id, case_name: item.name, scope: item.scope, asset_id: asset.id, asset_kind: asset.kind.rawValue, resolves_to: Array(Set(addresses)).sorted(), evidence: sources, collections: item.runs.filter { $0.domain == asset.value }))
        }
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(self)
    }
    var identity: String { "\(metadata.case_id)/\(metadata.asset_id)" }
    func fingerprint() throws -> String { SHA256.hash(data: try encoded()).map { String(format: "%02x", $0) }.joined() }
}

struct VaultOutbox: Codable {
    struct Entry: Codable {
        var record: VaultRecord
        var fingerprint: String
    }
    var pending: [String: Entry] = [:]
    var delivered: [String: String] = [:]
    var lastSuccess: Date?

    mutating func enqueue(_ cases: [Investigation]) throws {
        for item in cases {
            for record in VaultRecord.records(for: item) {
                let fingerprint = try record.fingerprint()
                if delivered[record.identity] != fingerprint {
                    pending[record.identity] = Entry(record: record, fingerprint: fingerprint)
                } else { pending.removeValue(forKey: record.identity) }
            }
        }
    }

    mutating func acknowledge(_ identity: String, fingerprint: String) {
        delivered[identity] = fingerprint
        if pending[identity]?.fingerprint == fingerprint { pending.removeValue(forKey: identity) }
        lastSuccess = Date()
    }
}

struct VaultConfiguration: Codable {
    var endpoint: String
    var apiKey: String
    var enabled: Bool
    var validEndpoint: URL? {
        guard enabled, let url = URL(string: endpoint), url.scheme == "https", url.host != nil,
              url.user == nil, url.password == nil, url.query == nil, url.fragment == nil else { return nil }
        return url
    }
    static var directory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0].appendingPathComponent("macOS-tools", isDirectory: true)
    }
    static func load() throws -> VaultConfiguration {
        let config = try JSONDecoder().decode(Self.self, from: Data(contentsOf: directory.appendingPathComponent("vault-config.json")))
        guard config.validEndpoint != nil, !config.apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw VaultError.configuration
        }
        return config
    }
}

enum VaultError: LocalizedError {
    case configuration, rejected(Int), invalidResponse
    var errorDescription: String? {
        switch self {
        case .configuration: return "Vault sync is disabled or not configured."
        case .rejected(let status): return "Vault returned HTTP \(status). Records remain queued."
        case .invalidResponse: return "Vault did not confirm acceptance. Records remain queued."
        }
    }
}

// Never forward the API key or investigation payload to an HTTP redirect target.
final class VaultRedirectPolicy: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

enum VaultTransport {
    static func send(_ entry: VaultOutbox.Entry, configuration: VaultConfiguration) async throws {
        guard let url = configuration.validEndpoint else { throw VaultError.configuration }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 10
        request.setValue(configuration.apiKey, forHTTPHeaderField: "X-API-Key")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(entry.fingerprint, forHTTPHeaderField: "Idempotency-Key")
        request.httpBody = try entry.record.encoded()
        let settings = URLSessionConfiguration.ephemeral
        settings.requestCachePolicy = .reloadIgnoringLocalCacheData
        settings.urlCache = nil
        settings.httpCookieStorage = nil
        let session = URLSession(configuration: settings, delegate: VaultRedirectPolicy(), delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        let (data, response) = try await session.data(for: request)
        guard let response = response as? HTTPURLResponse else { throw VaultError.invalidResponse }
        guard (200..<300).contains(response.statusCode) else { throw VaultError.rejected(response.statusCode) }
        if let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           object["success"] as? Bool == false || object["error"] != nil { throw VaultError.invalidResponse }
    }
}
