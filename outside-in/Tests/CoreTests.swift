import Foundation

func XCTAssertTrue(_ value: @autoclosure () -> Bool, _ message: String = "", file: StaticString = #file, line: UInt = #line) { precondition(value(), message, file: file, line: line) }
func XCTAssertFalse(_ value: @autoclosure () -> Bool, _ message: String = "", file: StaticString = #file, line: UInt = #line) { precondition(!value(), message, file: file, line: line) }
func XCTAssertEqual<T: Equatable>(_ left: T, _ right: T, _ message: String = "", file: StaticString = #file, line: UInt = #line) { precondition(left == right, message, file: file, line: line) }
func XCTAssertNil<T>(_ value: T?, _ message: String = "", file: StaticString = #file, line: UInt = #line) { precondition(value == nil, message, file: file, line: line) }
func XCTUnwrap<T>(_ value: T?) throws -> T { guard let value else { throw NSError(domain: "TestFailure", code: 1) }; return value }

@main struct CoreTests {
    static func main() throws {
        let tests = CoreTests()
        tests.testScopeRejectsLookalikes()
        tests.testDomainValidation()
        try tests.testDNSPreservesProvenanceAndCNAMEOwner()
        try tests.testNullMXDoesNotCreateEmptyAsset()
        tests.testFailedQueryRemainsAnInvestigationGap()
        try tests.testCaseRoundTripAndReport()
        try tests.testVaultPayload()
        try tests.testVaultRetryPersistenceAndDeduplication()
        try tests.testChangedEvidenceIsResent()
        try tests.testDemoNeverLeavesMac()
        tests.testIPTargetsAndReverseNames()
        tests.testScannerScopeAndModules()
        try tests.testCertificateNamesAndScope()
        try tests.testCertificateGraphLimit()
        try tests.testRDAPParsing()
        tests.testScannerResultsAndFailureIsolation()
        try tests.testScannerVaultPayload()
        try tests.testCertificateFallbackParsing()
        print("PASS: 18 core tests, including domain/IP validation, scanner parsing, certificate fallback, provenance, failures, Vault delivery state, and demo exclusion")
    }
    func testScopeRejectsLookalikes() {
        let item = Investigation(name: "Test", scope: "example.com")
        XCTAssertTrue(item.containsDomain("api.example.com"))
        XCTAssertTrue(item.containsDomain("EXAMPLE.COM."))
        XCTAssertFalse(item.containsDomain("notexample.com"))
        XCTAssertFalse(item.containsDomain("example.com.attacker.test"))
    }

    func testDomainValidation() {
        XCTAssertEqual(DomainInput.normalize(" https://Example.COM/path "), "example.com")
        for bad in ["-bad.example", "bad..example", "example.com;echo", "127.0.0.1", "https://user:password@example.com", "localhost", "a/b.example", "*.example.com"] {
            XCTAssertNil(DomainInput.normalize(bad), bad)
        }
    }

    func testDNSPreservesProvenanceAndCNAMEOwner() throws {
        let raw = #"{"Status":0,"Answer":[{"name":"www.example.com.","type":5,"TTL":300,"data":"edge.provider.test."},{"name":"edge.provider.test.","type":1,"TTL":30,"data":"192.0.2.3"}]}"#
        let response = try JSONDecoder().decode(DNSResponse.self, from: Data(raw.utf8))
        let result = DNSResult(type: "A", source: "https://cloudflare-dns.com/dns-query?name=www.example.com&type=A", raw: raw, response: response)
        var item = Investigation(name: "Test", scope: "example.com")
        DNSCollector.apply([result], domain: "www.example.com", to: &item)
        XCTAssertEqual(item.evidence.count, 2)
        let addressEdge = try XCTUnwrap(item.evidence.first { $0.relationship == "A record" })
        XCTAssertEqual(item.label(addressEdge.from), "edge.provider.test")
        XCTAssertEqual(item.runs.first?.rawResponse, raw)
        DNSCollector.apply([result], domain: "www.example.com", to: &item)
        XCTAssertEqual(item.evidence.count, 2, "Repeated identical collection must not duplicate graph edges")
        XCTAssertEqual(item.runs.count, 2, "Every collection must retain its raw response")
    }

    func testNullMXDoesNotCreateEmptyAsset() throws {
        let raw = #"{"Status":0,"Answer":[{"name":"example.com.","type":15,"TTL":300,"data":"0 ."}]}"#
        var item = Investigation(name: "Test", scope: "example.com")
        DNSCollector.apply([DNSResult(type: "MX", source: "https://example.com", raw: raw, response: try JSONDecoder().decode(DNSResponse.self, from: Data(raw.utf8)))], domain: "example.com", to: &item)
        XCTAssertEqual(item.assets.count, 1)
        XCTAssertTrue(item.evidence.isEmpty)
        XCTAssertEqual(item.runs.count, 1)
    }

    func testFailedQueryRemainsAnInvestigationGap() {
        var item = Investigation(name: "Test", scope: "example.com")
        _ = item.addAsset("example.com", kind: .domain)
        DNSCollector.apply([DNSResult(type: "A", source: "https://example.com", raw: "", error: "Timeout")], domain: "example.com", to: &item)
        XCTAssertTrue(item.evidence.isEmpty)
        XCTAssertTrue(item.leads.contains { $0.detail.contains("A, AAAA") })
    }

    func testCaseRoundTripAndReport() throws {
        let demo = Investigation.demo()
        let decoded = try JSONDecoder().decode(Investigation.self, from: JSONEncoder().encode(demo))
        XCTAssertEqual(decoded.assets, demo.assets)
        XCTAssertEqual(decoded.evidence.count, 6)
        let report = Reports.markdown(decoded)
        XCTAssertTrue(report.contains("TRAINING CASE"))
        XCTAssertTrue(report.contains("Hypothesis"))
        XCTAssertTrue(report.contains("https://northstar.example/training-fixture"))
    }

    func testVaultPayload() throws {
        var item = Investigation.demo()
        item.isDemo = false
        let records = VaultRecord.records(for: item)
        let staging = try XCTUnwrap(records.first { $0.value == "staging.northstar.example" })
        XCTAssertEqual(staging.source, "outside-in")
        XCTAssertEqual(staging.type, "subdomain")
        XCTAssertEqual(staging.metadata.resolves_to, ["192.0.2.24"])
        XCTAssertTrue(staging.metadata.evidence.contains { $0.status == "Hypothesis" })
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: staging.encoded()) as? [String: Any])
        XCTAssertEqual(object["source"] as? String, "outside-in")
        XCTAssertTrue(object["metadata"] != nil)
        let encoded = try staging.encoded()
        XCTAssertFalse(String(data: encoded, encoding: .utf8)!.contains("apiKey"))
    }

    func testVaultRetryPersistenceAndDeduplication() throws {
        var item = Investigation(name: "Test", scope: "example.com")
        _ = item.addAsset("example.com", kind: .domain)
        var queue = VaultOutbox()
        try queue.enqueue([item])
        let record = try XCTUnwrap(queue.pending.first)
        // A failed request does not acknowledge: round-trip the retry queue.
        var restored = try JSONDecoder().decode(VaultOutbox.self, from: JSONEncoder().encode(queue))
        XCTAssertEqual(restored.pending.count, 1)
        restored.acknowledge(record.key, fingerprint: record.value.fingerprint)
        try restored.enqueue([item])
        XCTAssertTrue(restored.pending.isEmpty)
        XCTAssertEqual(restored.delivered.count, 1)
    }

    func testChangedEvidenceIsResent() throws {
        var item = Investigation(name: "Test", scope: "example.com")
        let root = item.addAsset("example.com", kind: .domain)
        var queue = VaultOutbox()
        try queue.enqueue([item])
        let first = try XCTUnwrap(queue.pending.first)
        queue.acknowledge(first.key, fingerprint: first.value.fingerprint)
        item.evidence.append(Evidence(from: root, to: root, relationship: "TXT record", source: "https://example.com", excerpt: "v=spf1 -all", status: .observed))
        try queue.enqueue([item])
        XCTAssertEqual(queue.pending.count, 1)
        XCTAssertFalse(queue.pending[first.key]?.fingerprint == first.value.fingerprint)
        // An old acknowledgement must not erase a newer queued version.
        queue.acknowledge(first.key, fingerprint: first.value.fingerprint)
        XCTAssertEqual(queue.pending.count, 1)
    }

    func testDemoNeverLeavesMac() throws {
        var queue = VaultOutbox()
        try queue.enqueue([.demo()])
        XCTAssertTrue(queue.pending.isEmpty)
        XCTAssertTrue(VaultRecord.records(for: .demo()).isEmpty)
    }

    func testIPTargetsAndReverseNames() {
        XCTAssertEqual(TargetInput.ip("2001:0DB8:0:0::1"), "2001:db8::1")
        XCTAssertEqual(TargetInput.normalize(" 192.0.2.1 "), "192.0.2.1")
        XCTAssertEqual(TargetInput.normalize("HTTPS://Example.COM/path"), "example.com")
        XCTAssertEqual(TargetInput.reverseName("192.0.2.55"), "55.2.0.192.in-addr.arpa")
        XCTAssertEqual(TargetInput.reverseName("::1"), "1." + Array(repeating: "0", count: 31).joined(separator: ".") + ".ip6.arpa")
        for invalid in ["999.1.1.1", "1.1.1.1/24", "fe80::1%en0", "1.1.1.1; ls", "[::1]"] { XCTAssertNil(TargetInput.normalize(invalid), invalid) }
    }

    func testScannerScopeAndModules() {
        var domainCase = Investigation(name: "Test", scope: "example.com")
        XCTAssertTrue(domainCase.allowsScan("www.example.com"))
        XCTAssertFalse(domainCase.allowsScan("other.test"))
        XCTAssertFalse(domainCase.allowsScan("192.0.2.1"))
        _ = domainCase.addAsset("192.0.2.1", kind: .address)
        XCTAssertTrue(domainCase.allowsScan("192.0.2.1"))
        let ipCase = Investigation(name: "IP", scope: "2001:db8::1")
        XCTAssertTrue(ipCase.allowsScan("2001:0db8::1"))
        XCTAssertFalse(ipCase.allowsScan("host.2001:db8::1"))
        XCTAssertFalse(ipCase.containsDomain("2001:db8::1"))
        XCTAssertFalse(ScannerModule.dns.supports("::1"))
        XCTAssertTrue(ScannerModule.reverseDNS.supports("::1"))
        XCTAssertFalse(ScannerModule.defaults(for: "example.com").contains(.ports))
    }

    func testCertificateNamesAndScope() throws {
        let raw = #"[{"id":12,"name_value":"api.example.com\n*.example.com\nevil.test\nnotexample.com","issuer_name":"Test CA","not_before":"2025-01-01"},{"id":13,"name_value":"api.example.com\nwww.example.com","not_before":"2026-01-01"}]"#
        let result = try ReconScanner.certificateFindings(Data(raw.utf8), target: "example.com")
        XCTAssertEqual(result.total, 2)
        XCTAssertEqual(result.findings.map(\.value), ["api.example.com", "www.example.com"])
        XCTAssertTrue(result.findings.allSatisfy { $0.source == "https://crt.sh/?id=13" })
        XCTAssertTrue(result.findings[0].excerpt.contains("does not establish a live host"))
    }

    func testCertificateGraphLimit() throws {
        let rows = (0..<130).map { ["name_value": "h\($0).example.com"] }
        let result = try ReconScanner.certificateFindings(JSONSerialization.data(withJSONObject: rows), target: "example.com")
        XCTAssertEqual(result.total, 130)
        XCTAssertEqual(result.findings.count, 100)
    }

    func testRDAPParsing() throws {
        let raw = #"{"objectClassName":"ip network","handle":"TEST","startAddress":"192.0.2.0","endAddress":"192.0.2.255","country":"US","status":["active"],"events":[{"eventAction":"registration","eventDate":"2020-01-01"}]}"#
        let summary = try ReconScanner.rdapSummary(Data(raw.utf8))
        XCTAssertTrue(summary.contains("192.0.2.255"))
        XCTAssertTrue(summary.contains("not device geolocation"))
        do {
            _ = try ReconScanner.rdapSummary(Data(#"{"errorCode":404,"title":"Not found"}"#.utf8))
            preconditionFailure("RDAP errors must not produce successful evidence")
        } catch { /* Expected invalid source data. */ }
    }

    func testScannerResultsAndFailureIsolation() {
        var item = Investigation(name: "Test", scope: "example.com")
        let success = ScannerResult(module: .certificates, target: "example.com", source: "https://crt.sh/", raw: "[]", summary: "One certificate name", findings: [.init(value: "api.example.com", kind: .domain, relationship: "certificate log mentions", source: "https://crt.sh/?id=7", excerpt: "Historical certificate")])
        ReconScanner.apply(success, to: &item)
        ReconScanner.apply(success, to: &item)
        XCTAssertEqual(item.assets.count, 2)
        XCTAssertEqual(item.evidence.count, 2)
        XCTAssertEqual(item.runs.count, 2)
        ReconScanner.apply(.init(module: .rdap, target: "example.com", source: "https://rdap.org/", raw: "failure body", error: "Timeout"), to: &item)
        XCTAssertEqual(item.evidence.count, 2)
        XCTAssertTrue(item.runs.last!.outcome.hasPrefix("Failed"))
        XCTAssertEqual(item.runs.last!.rawResponse, "failure body")
        XCTAssertTrue(item.leads.contains { $0.detail.contains("Registration") })
    }

    func testScannerVaultPayload() throws {
        var item = Investigation(name: "IP", scope: "192.0.2.1")
        ReconScanner.apply(.init(module: .ports, target: "192.0.2.1", source: "tcp://192.0.2.1", raw: "port observation", summary: "443/tcp open"), to: &item)
        let record = try XCTUnwrap(VaultRecord.records(for: item).first)
        XCTAssertEqual(record.type, "ip")
        XCTAssertEqual(record.metadata.collections.first?.recordType, "TCP")
        XCTAssertEqual(record.metadata.collections.first?.rawResponse, "port observation")
        XCTAssertEqual(record.metadata.evidence.first?.source_url, "tcp://192.0.2.1")
    }

    func testCertificateFallbackParsing() throws {
        let raw = #"[{"dns_names":["api.example.com","*.example.com","other.test"],"issuer":{"name":"Example CA"},"not_before":"2026-01-01","not_after":"2027-01-01"}]"#
        let source = "https://api.certspotter.com/v1/issuances?domain=example.com"
        let parsed = try ReconScanner.spotterFindings(Data(raw.utf8), target: "example.com", source: source)
        XCTAssertEqual(parsed.total, 1)
        XCTAssertEqual(parsed.findings.first?.value, "api.example.com")
        XCTAssertEqual(parsed.findings.first?.source, source)
        XCTAssertTrue(parsed.findings.first!.excerpt.contains("Example CA"))
    }
}
