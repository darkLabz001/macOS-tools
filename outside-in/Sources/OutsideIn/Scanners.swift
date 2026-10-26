import Foundation
import Darwin
import Network
import Security
import CryptoKit

enum TargetInput {
    static func ip(_ input: String) -> String? {
        let value = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty, value.allSatisfy({ $0.isASCII && ($0.isHexDigit || $0 == "." || $0 == ":") }) else { return nil }
        var v4 = in_addr(); var v6 = in6_addr()
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        if inet_pton(AF_INET, value, &v4) == 1 {
            inet_ntop(AF_INET, &v4, &buffer, socklen_t(buffer.count))
        } else if inet_pton(AF_INET6, value, &v6) == 1 {
            inet_ntop(AF_INET6, &v6, &buffer, socklen_t(buffer.count))
        } else { return nil }
        return String(cString: buffer)
    }
    static func normalize(_ value: String) -> String? { ip(value) ?? DomainInput.normalize(value) }
    static func reverseName(_ value: String) -> String? {
        guard let normalized = ip(value) else { return nil }
        if normalized.contains(":") {
            var address = in6_addr()
            inet_pton(AF_INET6, normalized, &address)
            let hex = withUnsafeBytes(of: &address) { $0.map { String(format: "%02x", $0) }.joined() }
            return hex.reversed().map(String.init).joined(separator: ".") + ".ip6.arpa"
        }
        return normalized.split(separator: ".").reversed().joined(separator: ".") + ".in-addr.arpa"
    }
}

enum ScannerModule: String, CaseIterable, Identifiable, Codable {
    case dns = "DNS", rdap = "RDAP", certificates = "CT", reverseDNS = "PTR", web = "HTTPS", ports = "TCP"
    var id: String { rawValue }
    var title: String {
        switch self {
        case .dns: return "DNS records"
        case .rdap: return "Registration & network owner"
        case .certificates: return "Certificate-log discovery"
        case .reverseDNS: return "Reverse DNS"
        case .web: return "HTTPS headers & TLS"
        case .ports: return "Common TCP services"
        }
    }
    var detail: String {
        switch self {
        case .dns: return "A, AAAA, CNAME, MX, NS and TXT via Cloudflare."
        case .rdap: return "Registry status, dates, registrar or IP allocation via RDAP."
        case .certificates: return "Public certificate names via crt.sh, with Cert Spotter fallback; up to 100 graph nodes."
        case .reverseDNS: return "Look up the PTR name for an IPv4 or IPv6 address."
        case .web: return "Contact HTTPS port 443; record response headers and certificate chain fingerprints."
        case .ports: return "Connect to ports 21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 3389, 5432, 8080, 8443."
        }
    }
    var icon: String {
        switch self {
        case .dns: return "globe"
        case .rdap: return "building.2"
        case .certificates: return "checkmark.seal"
        case .reverseDNS: return "arrow.uturn.backward"
        case .web: return "lock.shield"
        case .ports: return "network"
        }
    }
    func supports(_ target: String) -> Bool {
        let isIP = TargetInput.ip(target) != nil
        switch self {
        case .dns, .certificates: return !isIP
        case .reverseDNS: return isIP
        default: return true
        }
    }
    static func defaults(for target: String) -> Set<Self> {
        TargetInput.ip(target) == nil ? [.dns, .rdap, .certificates, .web] : [.rdap, .reverseDNS]
    }
}

struct ScannerFinding {
    var value: String
    var kind: AssetKind
    var relationship: String
    var source: String
    var excerpt: String
}

struct ScannerResult {
    var module: ScannerModule
    var target: String
    var source: String
    var raw: String = ""
    var summary: String = ""
    var findings: [ScannerFinding] = []
    var error: String?
}

enum ScanError: LocalizedError {
    case http(Int), tooLarge, invalidData
    var errorDescription: String? {
        switch self {
        case .http(let status): return "Source returned HTTP \(status)."
        case .tooLarge: return "Source exceeded the 4 MB response limit."
        case .invalidData: return "Source returned unexpected data."
        }
    }
}

// Public-source lookups may follow HTTPS referrals. Direct web checks do not
// follow redirects, so a scan stays on the selected host.
final class ScannerHTTPPolicy: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    let allowReferrals: Bool
    private let lock = NSLock()
    private var certificates: [String] = []
    init(allowReferrals: Bool) { self.allowReferrals = allowReferrals }
    var certificateDetails: [String] { lock.lock(); defer { lock.unlock() }; return certificates }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(allowReferrals && request.url?.scheme == "https" ? request : nil)
    }
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        capture(challenge)
        completionHandler(.performDefaultHandling, nil)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        capture(challenge)
        completionHandler(.performDefaultHandling, nil)
    }
    private func capture(_ challenge: URLAuthenticationChallenge) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust, let trust = challenge.protectionSpace.serverTrust {
            // Materialize the evaluated chain before copying it. Authentication
            // still uses URLSession's default handling and hostname validation.
            _ = SecTrustEvaluateWithError(trust, nil)
            guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate] else { return }
            let details = chain.map { certificate in
                let subject = SecCertificateCopySubjectSummary(certificate) as String? ?? "Unknown subject"
                let fingerprint = SHA256.hash(data: SecCertificateCopyData(certificate) as Data).map { String(format: "%02x", $0) }.joined(separator: ":")
                return "Subject: \(subject); SHA256: \(fingerprint)"
            }
            lock.lock(); certificates = details; lock.unlock()
        }
    }
}

enum ScannerHTTP {
    struct Response { var data: Data; var response: HTTPURLResponse; var certificates: [String] }
    static func fetch(_ url: URL, method: String = "GET", referrals: Bool = true) async throws -> Response {
        let policy = ScannerHTTPPolicy(allowReferrals: referrals)
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 18
        config.timeoutIntervalForResource = 35
        config.httpCookieStorage = nil
        config.urlCache = nil
        let session = URLSession(configuration: config, delegate: policy, delegateQueue: nil)
        defer { session.finishTasksAndInvalidate() }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("OutsideIn/0.2 (OSINT research)", forHTTPHeaderField: "User-Agent")
        request.setValue("application/json, application/rdap+json, */*", forHTTPHeaderField: "Accept")
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse else { throw ScanError.invalidData }
        var data = Data()
        for try await byte in bytes {
            guard data.count < 4_000_000 else { session.invalidateAndCancel(); throw ScanError.tooLarge }
            data.append(byte)
        }
        return Response(data: data, response: http, certificates: policy.certificateDetails)
    }
}

enum ReconScanner {
    static func collect(_ module: ScannerModule, target: String) async -> ScannerResult {
        switch module {
        case .rdap: return await rdap(target)
        case .certificates: return await certificates(target)
        case .reverseDNS: return await reverseDNS(target)
        case .web: return await web(target)
        case .ports: return await ports(target)
        case .dns: return ScannerResult(module: .dns, target: target, source: "", error: "Use DNSCollector for DNS records.")
        }
    }

    static func apply(_ result: ScannerResult, to item: inout Investigation) {
        let root = item.addAsset(result.target, kind: TargetInput.ip(result.target) == nil ? .domain : .address)
        item.runs.append(CollectionRun(domain: result.target, recordType: result.module.rawValue, outcome: result.error.map { "Failed: \($0)" } ?? "Success: \(result.summary)", rawResponse: result.raw))
        guard result.error == nil else { return }
        func evidence(_ to: UUID, relation: String, source: String, excerpt: String) -> Evidence {
            Evidence(from: root, to: to, relationship: relation, source: source, excerpt: excerpt, status: .observed)
        }
        var additions = [evidence(root, relation: result.module.title, source: result.source, excerpt: result.summary)]
        for finding in result.findings {
            let target = item.addAsset(finding.value, kind: finding.kind)
            additions.append(evidence(target, relation: finding.relationship, source: finding.source, excerpt: finding.excerpt))
        }
        for addition in additions where !item.evidence.contains(where: { $0.from == addition.from && $0.to == addition.to && $0.relationship == addition.relationship && $0.source == addition.source && $0.excerpt == addition.excerpt }) {
            item.evidence.append(addition)
        }
    }

    static func rdap(_ target: String) async -> ScannerResult {
        let type = TargetInput.ip(target) == nil ? "domain" : "ip"
        let url = URL(string: "https://rdap.org/\(type)/\(target)")!
        var result = ScannerResult(module: .rdap, target: target, source: url.absoluteString)
        do {
            let response = try await ScannerHTTP.fetch(url)
            result.raw = String(data: response.data, encoding: .utf8) ?? ""
            result.source = response.response.url?.absoluteString ?? url.absoluteString
            guard (200..<300).contains(response.response.statusCode) else { throw ScanError.http(response.response.statusCode) }
            result.summary = try rdapSummary(response.data)
        } catch { result.error = error.localizedDescription }
        return result
    }

    static func rdapSummary(_ data: Data) throws -> String {
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], object["objectClassName"] != nil, object["errorCode"] == nil else { throw ScanError.invalidData }
        var lines: [String] = []
        for key in ["objectClassName", "ldhName", "name", "handle", "startAddress", "endAddress", "ipVersion", "country", "port43"] {
            if let value = object[key] as? String { lines.append("\(key): \(value)") }
        }
        if let status = object["status"] as? [String] { lines.append("Status: " + status.joined(separator: ", ")) }
        for event in object["events"] as? [[String: Any]] ?? [] {
            if let action = event["eventAction"] as? String, let date = event["eventDate"] as? String { lines.append("\(action): \(date)") }
        }
        for entity in object["entities"] as? [[String: Any]] ?? [] {
            let roles = entity["roles"] as? [String] ?? []
            guard roles.contains("registrar") || roles.contains("registrant") else { continue }
            let vcard = entity["vcardArray"] as? [Any]
            let rows = vcard?.last as? [[Any]] ?? []
            for row in rows where row.count >= 4 && ["fn", "org"].contains(row[0] as? String ?? "") {
                if let name = row[3] as? String { lines.append("\(roles.joined(separator: ", ")): \(name)") }
            }
        }
        if object["country"] != nil { lines.append("Country is a registration field, not device geolocation.") }
        return lines.joined(separator: "\n")
    }

    struct CTEntry: Decodable {
        var id: Int64?
        var name_value: String
        var issuer_name: String?
        var not_before: String?
        var not_after: String?
    }
    static func certificateFindings(_ data: Data, target: String) throws -> (findings: [ScannerFinding], total: Int) {
        let entries = try JSONDecoder().decode([CTEntry].self, from: data)
        var names: [String: CTEntry] = [:]
        for entry in entries.sorted(by: { ($0.not_before ?? "") > ($1.not_before ?? "") }) {
            for name in entry.name_value.components(separatedBy: .newlines) {
                guard let host = DomainInput.normalize(name), host == target || host.hasSuffix("." + target), names[host] == nil else { continue }
                names[host] = entry
            }
        }
        let findings = names.keys.sorted().prefix(100).map { host -> ScannerFinding in
            let entry = names[host]!
            let source = entry.id.map { "https://crt.sh/?id=\($0)" } ?? "https://crt.sh/"
            let text = "Certificate log mentions \(host). Issuer: \(entry.issuer_name ?? "unknown"). Validity: \(entry.not_before ?? "unknown") to \(entry.not_after ?? "unknown"). Historical certificate evidence does not establish a live host."
            return ScannerFinding(value: host, kind: .domain, relationship: "certificate log mentions", source: source, excerpt: text)
        }
        return (findings, names.count)
    }
    static func certificates(_ target: String) async -> ScannerResult {
        var url = URLComponents(string: "https://crt.sh/")!
        url.queryItems = [URLQueryItem(name: "q", value: "%." + target), URLQueryItem(name: "output", value: "json")]
        var result = ScannerResult(module: .certificates, target: target, source: url.url!.absoluteString)
        do {
            let response = try await ScannerHTTP.fetch(url.url!)
            result.raw = String(data: response.data, encoding: .utf8) ?? ""
            guard (200..<300).contains(response.response.statusCode) else { throw ScanError.http(response.response.statusCode) }
            let parsed = try certificateFindings(response.data, target: target)
            result.findings = parsed.findings
            result.summary = "\(parsed.total) unique hostnames in returned certificate records; \(parsed.findings.count) added to the graph. This is historical evidence, not a live-host check."
        } catch {
            let firstError = error.localizedDescription
            let firstRaw = result.raw
            var fallbackURL = URLComponents(string: "https://api.certspotter.com/v1/issuances")!
            fallbackURL.queryItems = [URLQueryItem(name: "domain", value: target), URLQueryItem(name: "include_subdomains", value: "true"), URLQueryItem(name: "expand", value: "dns_names"), URLQueryItem(name: "expand", value: "issuer")]
            result.source = fallbackURL.url!.absoluteString
            do {
                let response = try await ScannerHTTP.fetch(fallbackURL.url!)
                let secondRaw = String(data: response.data, encoding: .utf8) ?? ""
                let attempts: [String: String] = ["crt_sh_error": firstError, "crt_sh_response": firstRaw, "cert_spotter_response": secondRaw]
                result.raw = String(data: try JSONSerialization.data(withJSONObject: attempts, options: [.sortedKeys]), encoding: .utf8) ?? secondRaw
                guard (200..<300).contains(response.response.statusCode) else { throw ScanError.http(response.response.statusCode) }
                let parsed = try spotterFindings(response.data, target: target, source: result.source)
                result.findings = parsed.findings
                result.summary = "crt.sh unavailable (\(firstError)). Cert Spotter fallback returned \(parsed.total) unique names; \(parsed.findings.count) added. First page of unexpired issuances only, not exhaustive. Certificate evidence does not establish a live host."
            } catch { result.error = "crt.sh: \(firstError) Cert Spotter: \(error.localizedDescription)" }
        }
        return result
    }

    struct SpotterEntry: Decodable {
        struct Issuer: Decodable { var name: String? }
        var dns_names: [String]
        var issuer: Issuer?
        var not_before: String?
        var not_after: String?
    }
    static func spotterFindings(_ data: Data, target: String, source: String) throws -> (findings: [ScannerFinding], total: Int) {
        let entries = try JSONDecoder().decode([SpotterEntry].self, from: data)
        let converted = entries.map { entry -> [String: Any] in
            ["name_value": entry.dns_names.joined(separator: "\n"), "issuer_name": entry.issuer?.name ?? "unknown", "not_before": entry.not_before ?? "unknown", "not_after": entry.not_after ?? "unknown"]
        }
        var parsed = try certificateFindings(JSONSerialization.data(withJSONObject: converted), target: target)
        parsed.findings = parsed.findings.map { finding in var copy = finding; copy.source = source; return copy }
        return parsed
    }

    static func reverseDNS(_ target: String) async -> ScannerResult {
        guard let name = TargetInput.reverseName(target) else { return ScannerResult(module: .reverseDNS, target: target, source: "", error: "Enter a valid IP address.") }
        var url = URLComponents(string: "https://cloudflare-dns.com/dns-query")!
        url.queryItems = [URLQueryItem(name: "name", value: name), URLQueryItem(name: "type", value: "PTR")]
        var result = ScannerResult(module: .reverseDNS, target: target, source: url.url!.absoluteString)
        do {
            // Cloudflare's JSON endpoint requires its specific Accept header.
            var request = URLRequest(url: url.url!)
            request.setValue("application/dns-json", forHTTPHeaderField: "Accept")
            request.timeoutInterval = 15
            let (data, response) = try await URLSession.shared.data(for: request)
            result.raw = String(data: data, encoding: .utf8) ?? ""
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else { throw ScanError.invalidData }
            let parsed = try JSONDecoder().decode(DNSResponse.self, from: data)
            guard parsed.Status == 0 || parsed.Status == 3 else { throw ScanError.invalidData }
            let records = (parsed.Answer ?? []).filter { $0.type == 12 }
            result.findings = records.compactMap { answer in
                guard let host = DomainInput.normalize(answer.data) else { return nil }
                return ScannerFinding(value: host, kind: .domain, relationship: "PTR record", source: result.source, excerpt: "\(name) PTR \(host), TTL=\(answer.TTL). A reverse name does not establish ownership.")
            }
            result.summary = "\(result.findings.count) PTR hostname(s)." + (parsed.Status == 3 ? " Reverse name does not exist (NXDOMAIN)." : "")
        } catch { result.error = error.localizedDescription }
        return result
    }

    static func web(_ target: String) async -> ScannerResult {
        let host = target.contains(":") ? "[\(target)]" : target
        let url = URL(string: "https://\(host)/")!
        var result = ScannerResult(module: .web, target: target, source: url.absoluteString)
        do {
            let response = try await ScannerHTTP.fetch(url, method: "HEAD", referrals: false)
            let headers = response.response.allHeaderFields.reduce(into: [String: String]()) { $0[String(describing: $1.key).lowercased()] = String(describing: $1.value) }
            // Omit Set-Cookie values; a service inventory does not need session identifiers.
            let names = ["server", "content-type", "location", "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy", "x-powered-by"]
            var lines = ["HTTPS HEAD \(url.absoluteString)", "HTTP status: \(response.response.statusCode)", "Redirects are recorded, not followed."]
            for name in names { if let value = headers[name] { lines.append("\(name): \(value)") } }
            for name in ["strict-transport-security", "content-security-policy", "x-content-type-options"] where headers[name] == nil { lines.append("\(name): not present in this HEAD response (not a vulnerability determination)") }
            lines += response.certificates
            result.summary = lines.joined(separator: "\n")
            result.raw = result.summary
        } catch { result.error = error.localizedDescription }
        return result
    }

    static let commonPorts: [UInt16] = [21, 22, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]
    struct PortResult: Codable { var port: UInt16; var state: String; var detail: String }
    static func ports(_ target: String) async -> ScannerResult {
        var results: [PortResult] = []
        // Four concurrent connections; no address-range sweep or recursive scanning.
        for offset in stride(from: 0, to: commonPorts.count, by: 4) {
            let batch = commonPorts[offset..<min(offset + 4, commonPorts.count)]
            let next = await withTaskGroup(of: PortResult.self, returning: [PortResult].self) { group in
                for port in batch { group.addTask { await TCPProbe.check(target, port: port) } }
                var values: [PortResult] = []
                for await value in group { values.append(value) }
                return values
            }
            results += next
        }
        results.sort { $0.port < $1.port }
        let open = results.filter { $0.state == "open" }.map { String($0.port) }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let raw = (try? encoder.encode(results)).flatMap { String(data: $0, encoding: .utf8) } ?? ""
        let detail = results.map { "\($0.port)/tcp \($0.state): \($0.detail)" }.joined(separator: "\n")
        return ScannerResult(module: .ports, target: target, source: "tcp://\(target.contains(":") ? "[\(target)]" : target)", raw: raw, summary: "Open TCP ports: \(open.isEmpty ? "none observed" : open.joined(separator: ", ")). Port numbers do not identify software or prove vulnerabilities.\n\(detail)")
    }
}

private final class TCPProbe: @unchecked Sendable {
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "outside-in.tcp.\(UUID())")
    private var finished = false
    private var continuation: CheckedContinuation<ReconScanner.PortResult, Never>?
    private let port: UInt16
    init(_ host: String, port: UInt16) {
        self.port = port
        connection = NWConnection(host: NWEndpoint.Host(host), port: NWEndpoint.Port(rawValue: port)!, using: .tcp)
    }
    static func check(_ host: String, port: UInt16) async -> ReconScanner.PortResult {
        let probe = TCPProbe(host, port: port)
        return await probe.start()
    }
    private func start() async -> ReconScanner.PortResult {
        await withCheckedContinuation { continuation in
            queue.async { [self] in
                self.continuation = continuation
                self.connection.stateUpdateHandler = { [weak self] state in
                    guard let self else { return }
                    switch state {
                    case .ready: self.finish("open", "TCP connection established")
                    case .failed(let error):
                        if case .posix(let code) = error, code == .ECONNREFUSED { self.finish("closed", "Connection refused") }
                        else { self.finish("unreachable", error.localizedDescription) }
                    default: break
                    }
                }
                self.connection.start(queue: self.queue)
                self.queue.asyncAfter(deadline: .now() + 3) { self.finish("timeout", "No connection within 3 seconds; may be filtered or unavailable") }
            }
        }
    }
    private func finish(_ state: String, _ detail: String) {
        guard !finished else { return }
        finished = true
        connection.stateUpdateHandler = nil
        connection.cancel()
        continuation?.resume(returning: .init(port: port, state: state, detail: detail))
        continuation = nil
    }
}
