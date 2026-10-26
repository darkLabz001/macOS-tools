import Foundation

struct DNSResponse: Decodable {
    struct Answer: Decodable {
        let name: String
        let type: Int
        let TTL: Int
        let data: String
    }
    let Status: Int
    let Answer: [Answer]?
}

struct DNSResult {
    var type: String
    var source: String
    var raw: String
    var response: DNSResponse?
    var error: String?
}

enum DNSCollector {
    static let recordTypes = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

    static func collect(domain: String) async -> [DNSResult] {
        await withTaskGroup(of: DNSResult.self, returning: [DNSResult].self) { group in
            for type in recordTypes {
                group.addTask {
                    var components = URLComponents(string: "https://cloudflare-dns.com/dns-query")!
                    components.queryItems = [URLQueryItem(name: "name", value: domain), URLQueryItem(name: "type", value: type)]
                    let url = components.url!
                    var request = URLRequest(url: url)
                    request.setValue("application/dns-json", forHTTPHeaderField: "Accept")
                    request.timeoutInterval = 15
                    do {
                        let (data, response) = try await URLSession.shared.data(for: request)
                        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                            throw URLError(.badServerResponse)
                        }
                        guard data.count <= 1_000_000 else { throw URLError(.dataLengthExceedsMaximum) }
                        let raw = String(data: data, encoding: .utf8) ?? ""
                        let decoded = try JSONDecoder().decode(DNSResponse.self, from: data)
                        return DNSResult(type: type, source: url.absoluteString, raw: raw, response: decoded)
                    } catch {
                        return DNSResult(type: type, source: url.absoluteString, raw: "", error: error.localizedDescription)
                    }
                }
            }
            var results: [DNSResult] = []
            for await result in group { results.append(result) }
            return results.sorted { $0.type < $1.type }
        }
    }

    static func apply(_ results: [DNSResult], domain: String, to investigation: inout Investigation) {
        let root = investigation.addAsset(domain, kind: .domain)
        for result in results {
            let outcome: String
            if let error = result.error { outcome = "Failed: \(error)" }
            else if let response = result.response, response.Status == 0 {
                outcome = "Success: \(response.Answer?.count ?? 0) answer(s)"
            } else { outcome = "DNS status \(result.response?.Status ?? -1)" }
            investigation.runs.append(CollectionRun(domain: domain, recordType: result.type, outcome: outcome, rawResponse: result.raw))
            guard let response = result.response, response.Status == 0 else { continue }
            for answer in response.Answer ?? [] {
                let kind: AssetKind
                let value: String
                let relation: String
                switch answer.type {
                case 1: kind = .address; value = answer.data; relation = "A record"
                case 28: kind = .address; value = answer.data; relation = "AAAA record"
                case 5: kind = .domain; value = answer.data.trimmingCharacters(in: CharacterSet(charactersIn: ".")); relation = "CNAME record"
                case 15:
                    // A null MX record explicitly declares that the domain accepts no mail.
                    guard let host = answer.data.split(whereSeparator: \.isWhitespace).last, host != "." else { continue }
                    kind = .mailserver; value = String(host).trimmingCharacters(in: CharacterSet(charactersIn: ".")); relation = "MX record"
                case 2: kind = .nameserver; value = answer.data.trimmingCharacters(in: CharacterSet(charactersIn: ".")); relation = "NS record"
                case 16:
                    // Keep TXT content as evidence on the domain, rather than inventing an asset.
                    kind = .domain; value = answer.name.trimmingCharacters(in: CharacterSet(charactersIn: ".")); relation = "TXT record"
                default: continue
                }
                let ownerName = answer.name.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
                let owner = ownerName == domain ? root : investigation.addAsset(ownerName, kind: .domain)
                let target = investigation.addAsset(value, kind: kind)
                let excerpt = "\(answer.name) TTL=\(answer.TTL) TYPE=\(answer.type) \(answer.data)"
                // Preserve each collection's raw response; avoid duplicate graph edges.
                if !investigation.evidence.contains(where: { $0.from == owner && $0.to == target && $0.relationship == relation && $0.excerpt == excerpt }) {
                    investigation.evidence.append(Evidence(from: owner, to: target, relationship: relation, source: result.source, excerpt: excerpt, status: .observed))
                }
            }
        }
    }
}
