import AppKit
import Foundation
import UniformTypeIdentifiers
import Darwin

enum Backend {
    static let tshark = "/opt/homebrew/bin/tshark"
    static let aircrack = "/opt/homebrew/bin/aircrack-ng"
    static let lists = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/macOS-tools/wordlists")
    static let rockyou = lists.appendingPathComponent("rockyou.txt")
    static let seclists = lists.appendingPathComponent("SecLists/Passwords", isDirectory: true)
    static func bssid(_ value: String) -> String? {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return text.range(of: "^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", options: .regularExpression) == nil ? nil : text
    }
    static func preview(_ path: String, filter: String) -> [String] {
        var args = ["-n", "-r", path, "-c", "10000"]
        if !filter.isEmpty { args += ["-Y", filter] }
        args += ["-T", "fields", "-E", "header=y", "-E", "separator=/t", "-E", "escape=y"]
        for field in ["frame.number", "frame.time_relative", "_ws.col.protocol", "_ws.col.def_src", "_ws.col.def_dst", "frame.len", "wlan.bssid", "wlan.ssid", "_ws.col.info"] {
            args += ["-e", field]
        }
        return args
    }
    static func crack(_ path: String, words: String, target: String) -> [String] {
        ["-a", "2", "-b", target, "-w", words, "-p", "4", path]
    }
    static func inventory(_ path: String) -> [String] {
        var args = ["-n", "-r", path, "-Y", "wlan.bssid && (wlan.fc.type_subtype == 8 || wlan.fc.type_subtype == 5 || eapol)", "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f"]
        for name in ["wlan.bssid", "wlan.ssid", "wlan.sa", "wlan.da", "wlan_rsna_eapol.keydes.msgnr", "eapol.keydes.replay_counter", "wlan.rsn.akms.type"] { args += ["-e", name] }
        return args
    }
    static func validateFile(_ path: String) -> Bool {
        var directory: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &directory)
            && !directory.boolValue && FileManager.default.isReadableFile(atPath: path)
    }
}

struct WiFiTarget: Codable {
    var bssid: String
    var ssid = "Hidden / unknown SSID"
    var akms: Set<Int> = []
    var clients: [String: [Int: Set<UInt64>]] = [:]
    var candidate: Bool {
        clients.values.contains { messages in
            let first = messages[1] ?? [], second = messages[2] ?? [], third = messages[3] ?? []
            return !first.isDisjoint(with: second) || second.contains { $0 < UInt64.max && third.contains($0 + 1) }
        }
    }
    var readiness: String {
        if !akms.isEmpty && akms.isDisjoint(with: [2, 4, 6]) {
            return akms.contains(8) || akms.contains(9) ? "WPA3-SAE — wordlist check unsupported" : "Enterprise / non-PSK — unsupported"
        }
        return candidate ? "Handshake candidate — backend must verify" : "No matched EAPOL pair found"
    }
}

final class CaptureInventory {
    var targets: [String: WiFiTarget] = [:]
    var pending = ""
    func feed(_ chunk: String) {
        pending += chunk
        let lines = pending.components(separatedBy: "\n")
        pending = lines.last ?? ""
        for line in lines.dropLast() { consume(line) }
    }
    func finish() { if !pending.isEmpty { consume(pending); pending = "" } }
    func consume(_ line: String) {
        let fields = line.components(separatedBy: "\t")
        guard fields.count >= 7, let bssid = Backend.bssid(fields[0]) else { return }
        var ap = targets[bssid] ?? WiFiTarget(bssid: bssid)
        let hex = fields[1].replacingOccurrences(of: ":", with: "")
        if !hex.isEmpty, hex.count % 2 == 0 {
            var bytes: [UInt8] = []
            var offset = hex.startIndex
            while offset < hex.endIndex {
                let end = hex.index(offset, offsetBy: 2)
                if let byte = UInt8(hex[offset..<end], radix: 16) { bytes.append(byte) }
                offset = end
            }
            if bytes.contains(where: { $0 != 0 }) { ap.ssid = String(decoding: bytes, as: UTF8.self) }
        }
        if let akm = Int(fields[6]) { ap.akms.insert(akm) }
        if let message = Int(fields[4]), let counter = UInt64(fields[5]) {
            let client = fields[2].lowercased() == bssid ? fields[3].lowercased() : fields[2].lowercased()
            if Backend.bssid(client) != nil {
                ap.clients[client, default: [:]][message, default: []].insert(counter)
            }
        }
        targets[bssid] = ap
    }
    var sorted: [WiFiTarget] {
        targets.values.sorted { $0.candidate != $1.candidate ? $0.candidate : $0.bssid < $1.bssid }
    }
}

struct InventoryReport: Encodable {
    let bssid: String
    let ssid: String
    let handshakeCandidate: Bool
    let readiness: String
}

final class PacketVault: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    let capture = NSTextField(string: "")
    let wordlist = NSTextField(string: "")
    let target = NSTextField(string: "")
    let filter = NSTextField(string: "")
    let frame = NSTextField(string: "1")
    let targetPicker = NSPopUpButton()
    var discoveredTargets: [WiFiTarget] = []
    let vaultStatus = NSTextField(labelWithString: "Vault · connecting")
    let status = NSTextField(labelWithString: "IDLE · Open a capture to begin")
    let output = NSTextView()
    var controls: [NSControl] = []
    var stopButton: NSButton!
    var process: Process?
    var cancelled = false
    var jobDirectory: URL?
    let green = NSColor(calibratedRed: 0.55, green: 1, blue: 0.16, alpha: 1)

    func applicationDidFinishLaunching(_ notification: Notification) {
        if let url = Bundle.main.url(forResource: "PacketVault", withExtension: "icns"),
           let icon = NSImage(contentsOf: url) { NSApp.applicationIconImage = icon }
        NSApp.appearance = NSAppearance(named: .darkAqua)
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1120, height: 850),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Packet Vault"
        window.minSize = NSSize(width: 1000, height: 720)
        window.center()
        let root = NSStackView()
        root.orientation = .vertical
        root.alignment = .leading
        root.spacing = 13
        root.edgeInsets = NSEdgeInsets(top: 24, left: 24, bottom: 22, right: 24)
        root.translatesAutoresizingMaskIntoConstraints = false
        let content = window.contentView!
        content.wantsLayer = true
        content.layer?.backgroundColor = NSColor(calibratedWhite: 0.045, alpha: 1).cgColor
        content.addSubview(root)
        NSLayoutConstraint.activate([root.leadingAnchor.constraint(equalTo: content.leadingAnchor), root.trailingAnchor.constraint(equalTo: content.trailingAnchor), root.topAnchor.constraint(equalTo: content.topAnchor), root.bottomAnchor.constraint(equalTo: content.bottomAnchor)])
        let title = NSTextField(labelWithString: "PACKET VAULT  //  OFFLINE LAB")
        title.font = .monospacedSystemFont(ofSize: 25, weight: .bold)
        title.textColor = green
        let iconView = NSImageView()
        iconView.image = NSApp.applicationIconImage
        iconView.imageScaling = .scaleProportionallyUpOrDown
        iconView.widthAnchor.constraint(equalToConstant: 52).isActive = true
        iconView.heightAnchor.constraint(equalToConstant: 52).isActive = true
        let brand = NSStackView(views: [iconView, title])
        brand.spacing = 12
        root.addArrangedSubview(brand)
        vaultStatus.textColor = .secondaryLabelColor
        root.addArrangedSubview(vaultStatus)
        VaultRelay.start { [weak self] in self?.vaultStatus.stringValue = $0 }
        let subtitle = NSTextField(wrappingLabelWithString: "Inspect captures. Check WPA/WPA2-Personal passwords with your wordlist. Analysis runs locally. Structured findings sync to your OSINT Vault.")
        subtitle.textColor = .secondaryLabelColor
        root.addArrangedSubview(subtitle)
        capture.placeholderString = "Choose a .pcap, .pcapng, or .cap file"
        wordlist.placeholderString = "Choose a plain-text wordlist"
        target.placeholderString = "AP BSSID, e.g. 02:11:22:33:44:55"
        filter.placeholderString = "Wireshark display filter, e.g. eapol or dns"
        root.addArrangedSubview(row("CAPTURE", capture, button("Open…", #selector(openCapture))))
        root.addArrangedSubview(row("WORDLIST", wordlist, button("Choose…", #selector(openWordlist))))
        let presets = NSStackView(views: [NSTextField(labelWithString: "WORDLIST LIBRARY"), button("Use rockyou", #selector(useRockyou)), button("Choose from SecLists…", #selector(openSecLists))])
        presets.spacing = 12
        root.addArrangedSubview(presets)
        if Backend.validateFile(Backend.rockyou.path) { wordlist.stringValue = Backend.rockyou.path }
        root.addArrangedSubview(row("TARGET AP", target))
        targetPicker.addItem(withTitle: "Find Wi-Fi targets to populate this list")
        targetPicker.target = self
        targetPicker.action = #selector(selectDiscoveredTarget)
        targetPicker.widthAnchor.constraint(greaterThanOrEqualToConstant: 650).isActive = true
        let discovery = NSStackView(views: [button("Find Wi-Fi targets", #selector(findTargets)), targetPicker])
        discovery.spacing = 12
        root.addArrangedSubview(discovery)
        root.addArrangedSubview(row("DISPLAY FILTER", filter))
        let actions = NSStackView(views: [button("Packet list", #selector(packets)), button("Protocol summary", #selector(summary)), NSTextField(labelWithString: "Frame"), frame, button("Packet details", #selector(details)), button("Start wordlist check", #selector(crack))])
        actions.spacing = 10
        frame.widthAnchor.constraint(equalToConstant: 70).isActive = true
        root.addArrangedSubview(actions)
        stopButton = button("Stop current job", #selector(stop))
        stopButton.isEnabled = false
        stopButton.contentTintColor = .systemRed
        let stateRow = NSStackView(views: [status, stopButton])
        stateRow.spacing = 20
        status.font = .monospacedSystemFont(ofSize: 12, weight: .medium)
        status.textColor = green
        root.addArrangedSubview(stateRow)
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.hasHorizontalScroller = true
        scroll.borderType = .bezelBorder
        output.isEditable = false
        output.isSelectable = true
        output.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        output.textColor = NSColor(calibratedRed: 0.76, green: 0.91, blue: 0.72, alpha: 1)
        output.backgroundColor = NSColor(calibratedWhite: 0.025, alpha: 1)
        output.isHorizontallyResizable = true
        output.isVerticallyResizable = true
        output.textContainer?.widthTracksTextView = false
        output.textContainer?.containerSize = NSSize(width: 100000, height: 10000000)
        output.textContainerInset = NSSize(width: 12, height: 12)
        scroll.documentView = output
        root.addArrangedSubview(scroll)
        scroll.widthAnchor.constraint(equalTo: root.widthAnchor, constant: -48).isActive = true
        scroll.heightAnchor.constraint(greaterThanOrEqualToConstant: 230).isActive = true
        let note = NSTextField(wrappingLabelWithString: "Viewing supports general PCAPs. Wordlist checking needs a usable WPA/WPA2-Personal handshake and the correct AP BSSID. WPA3-SAE, Enterprise, and arbitrary encrypted traffic are not supported. Use captures you own or are authorized to analyze.")
        note.font = .systemFont(ofSize: 11)
        note.textColor = .secondaryLabelColor
        root.addArrangedSubview(note)
        controls += [capture, wordlist, target, filter, frame, targetPicker]
        append("READY\n\n1. Open a capture.\n2. Click Find Wi-Fi targets, then choose an AP from the list.\n3. Review its handshake-candidate status and choose a wordlist.\n4. Click Start wordlist check; Stop current job cancels it.\n\nPacket list, Protocol summary, and Packet details are available separately.\nNo live capture or password checking starts automatically.\nStructured metadata syncs to your OSINT Vault.\nPacket list and protocol summary inspect the first 10,000 input frames.\nTarget inventory and packet details read the full capture.\nPasswords are shown in this window only; no recovered-key file is created.\n")
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }
    func button(_ label: String, _ action: Selector) -> NSButton {
        let b = NSButton(title: label, target: self, action: action)
        b.bezelStyle = .rounded
        controls.append(b)
        return b
    }
    func row(_ label: String, _ field: NSTextField, _ browse: NSButton? = nil) -> NSStackView {
        let caption = NSTextField(labelWithString: label)
        caption.font = .monospacedSystemFont(ofSize: 11, weight: .medium)
        caption.textColor = .secondaryLabelColor
        caption.widthAnchor.constraint(equalToConstant: 120).isActive = true
        var views: [NSView] = [caption, field]
        if let browse { views.append(browse) }
        let stack = NSStackView(views: views)
        stack.spacing = 12
        field.widthAnchor.constraint(greaterThanOrEqualToConstant: 550).isActive = true
        return stack
    }
    func choose(_ field: NSTextField, captureFile: Bool, directory: URL? = nil) {
        guard process == nil else { return }
        let panel = NSOpenPanel()
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.directoryURL = directory ?? (captureFile ? nil : Backend.lists)
        if captureFile { panel.allowedContentTypes = ["pcap", "pcapng", "cap"].compactMap { UTType(filenameExtension: $0) } }
        panel.beginSheetModal(for: window) { result in
            if result == .OK, let url = panel.url { field.stringValue = url.path }
        }
    }
    @objc func openCapture() { choose(capture, captureFile: true) }
    @objc func openWordlist() { choose(wordlist, captureFile: false) }
    @objc func openSecLists() {
        guard FileManager.default.fileExists(atPath: Backend.seclists.path) else { alert("SecLists is not installed at \(Backend.seclists.path)"); return }
        choose(wordlist, captureFile: false, directory: Backend.seclists)
    }
    @objc func useRockyou() {
        guard Backend.validateFile(Backend.rockyou.path) else { alert("rockyou.txt is not installed at \(Backend.rockyou.path)"); return }
        wordlist.stringValue = Backend.rockyou.path
    }
    func capturePath() -> String? {
        let path = (capture.stringValue as NSString).expandingTildeInPath
        guard Backend.validateFile(path) else { alert("Choose a readable capture file first."); return nil }
        return path
    }
    func alert(_ message: String) {
        let a = NSAlert(); a.messageText = message
        a.beginSheetModal(for: window)
    }
    func append(_ text: String) {
        output.textStorage?.append(NSAttributedString(string: text, attributes: [.font: output.font!, .foregroundColor: output.textColor!]))
        if let storage = output.textStorage, storage.length > 1000000 {
            storage.deleteCharacters(in: NSRange(location: 0, length: storage.length - 900000))
        }
        output.scrollToEndOfDocument(nil)
    }
    func busy(_ value: Bool, _ label: String) {
        for control in controls { control.isEnabled = !value }
        stopButton.isEnabled = value
        status.stringValue = label
    }
    func run(_ executable: String, _ args: [String], label: String, onText: ((String) -> Void)? = nil, done: ((Int32) -> Void)? = nil) {
        guard process == nil else { return }
        guard FileManager.default.isExecutableFile(atPath: executable) else { alert("Missing executable: \(executable)"); cleanup(); return }
        let p = Process()
        let pipe = Pipe()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = args
        p.standardOutput = pipe
        p.standardError = pipe
        p.standardInput = FileHandle.nullDevice
        p.environment = ProcessInfo.processInfo.environment.merging(["TERM": "dumb", "NO_COLOR": "1"]) { _, new in new }
        process = p
        busy(true, "RUNNING · \(label)")
        append("\n── \(label) ──\n")
        do { try p.run() } catch {
            process = nil; busy(false, "FAILED · Could not start job")
            append("\(error.localizedDescription)\n"); cleanup(); return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            while true {
                let bytes = pipe.fileHandleForReading.availableData
                if bytes.isEmpty { break }
                let text = String(decoding: bytes, as: UTF8.self)
                    .replacingOccurrences(of: "\u{001B}\\[[0-?]*[ -/]*[@-~]", with: "", options: .regularExpression)
                    .replacingOccurrences(of: "\r", with: "\n")
                DispatchQueue.main.async { self.append(text); onText?(text) }
            }
            p.waitUntilExit()
            DispatchQueue.main.async {
                guard self.process === p else { return }
                self.process = nil
                self.busy(false, self.cancelled ? "STOPPED · Job cancelled" : "FINISHED · Exit \(p.terminationStatus)")
                self.append("\n[\(self.cancelled ? "Stopped" : "Finished"), exit \(p.terminationStatus)]\n")
                if let done { done(p.terminationStatus) } else { self.cleanup() }
            }
        }
    }
    @objc func packets() {
        guard let path = capturePath() else { return }
        cancelled = false
        let selectedFilter = filter.stringValue
        run(Backend.tshark, Backend.preview(path, filter: selectedFilter), label: "Packet list · first 10,000 input frames", done: { code in
            if code == 0 && !self.cancelled { self.collectVaultEndpoints(path, filter: selectedFilter) }
            self.cleanup()
        })
    }
    @objc func findTargets() {
        guard let path = capturePath() else { return }
        cancelled = false
        let inventory = CaptureInventory()
        run(Backend.tshark, Backend.inventory(path), label: "Wi-Fi target and handshake inventory · full capture", onText: { inventory.feed($0) }) { [self] code in
            inventory.finish()
            guard code == 0, !self.cancelled else { return }
            self.discoveredTargets = inventory.sorted
            let targets = inventory.sorted.map { ["bssid": $0.bssid, "ssid": $0.ssid, "handshakeCandidate": $0.candidate, "readiness": $0.readiness] as [String: Any] }
            if let data = try? JSONSerialization.data(withJSONObject: ["capture": URL(fileURLWithPath: path).lastPathComponent, "targets": targets]) {
                VaultRelay.submit("packet-wifi", data: data) { [weak self] in self?.vaultStatus.stringValue = $0 }
            }
            self.targetPicker.removeAllItems()
            for ap in self.discoveredTargets {
                self.targetPicker.addItem(withTitle: "\(ap.ssid) · \(ap.bssid) · \(ap.readiness)")
            }
            if self.discoveredTargets.isEmpty {
                self.targetPicker.addItem(withTitle: "No Wi-Fi APs found — capture may lack 802.11 headers")
                self.target.stringValue = ""
            } else { self.selectDiscoveredTarget() }
            self.append("\nFound \(self.discoveredTargets.count) AP(s). Matching EAPOL pairs are candidates, not a guarantee of password recovery.\n")
        }
    }
    @objc func selectDiscoveredTarget() {
        let index = targetPicker.indexOfSelectedItem
        guard discoveredTargets.indices.contains(index) else { return }
        let ap = discoveredTargets[index]
        target.stringValue = ap.bssid
        append("\nSelected \(ap.ssid) · \(ap.bssid): \(ap.readiness)\n")
    }
    @objc func summary() {
        guard let path = capturePath() else { return }
        cancelled = false
        run(Backend.tshark, ["-n", "-r", path, "-c", "10000", "-q", "-z", "io,phs"], label: "Protocol summary · first 10,000 input frames", done: { code in
            if code == 0 && !self.cancelled { self.collectVaultEndpoints(path, filter: "") }
            self.cleanup()
        })
    }
    @objc func details() {
        guard let path = capturePath() else { return }
        guard let number = Int(frame.stringValue), number > 0 else { alert("Enter a positive frame number."); return }
        cancelled = false
        run(Backend.tshark, ["-n", "-r", path, "-Y", "frame.number == \(number)", "-V", "-x"], label: "Packet details · frame \(number)")
    }
    func collectVaultEndpoints(_ path: String, filter: String) {
        DispatchQueue.global(qos: .utility).async { [self] in
            let process = Process(), pipe = Pipe()
            process.executableURL = URL(fileURLWithPath: Backend.tshark)
            var args = ["-n", "-r", path, "-c", "10000", "-T", "fields", "-E", "occurrence=f", "-E", "separator=/t"]
            if !filter.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { args += ["-Y", filter] }
            for field in ["ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport", "_ws.col.Protocol"] { args += ["-e", field] }
            process.arguments = args; process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice; process.standardInput = FileHandle.nullDevice
            do {
                try process.run()
                let rows = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                process.waitUntilExit()
                guard process.terminationStatus == 0 else { return }
                let data = try JSONSerialization.data(withJSONObject: ["capture": URL(fileURLWithPath: path).lastPathComponent, "rows": rows])
                VaultRelay.submit("packet-endpoints", data: data) { [weak self] in self?.vaultStatus.stringValue = $0 }
            } catch { DispatchQueue.main.async { self.vaultStatus.stringValue = "Vault · endpoint extraction failed; capture remains local" } }
        }
    }

    @objc func crack() {
        guard let path = capturePath() else { return }
        let words = (wordlist.stringValue as NSString).expandingTildeInPath
        guard Backend.validateFile(words) else { alert("Choose a readable plain-text wordlist."); return }
        guard let bssid = Backend.bssid(target.stringValue) else { alert("Enter one AP BSSID in aa:bb:cc:dd:ee:ff format."); return }
        cancelled = false
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("packet-vault-\(UUID().uuidString)", isDirectory: true)
        do { try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true) }
        catch { alert(error.localizedDescription); return }
        jobDirectory = dir
        let converted = dir.appendingPathComponent("capture.pcap").path
        run(Backend.tshark, ["-n", "-r", path, "-F", "pcap", "-w", converted], label: "Preparing a temporary PCAP copy", done: { code in
            guard code == 0, !self.cancelled else { self.cleanup(); return }
            self.run(Backend.aircrack, Backend.crack(converted, words: words, target: bssid), label: "WPA/WPA2 wordlist check · \(bssid)")
        })
    }
    @objc func stop() {
        cancelled = true
        guard let p = process, p.isRunning else { return }
        status.stringValue = "STOPPING · Waiting for current job"
        p.terminate()
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            if self.process === p && p.isRunning { Darwin.kill(p.processIdentifier, SIGKILL) }
        }
    }
    func cleanup() {
        if let dir = jobDirectory { try? FileManager.default.removeItem(at: dir) }
        jobDirectory = nil
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) { stop(); cleanup() }
}

if let index = CommandLine.arguments.firstIndex(of: "--inspect-targets") {
    guard CommandLine.arguments.count > index + 1 else { exit(2) }
    let p = Process(), pipe = Pipe()
    p.executableURL = URL(fileURLWithPath: Backend.tshark)
    p.arguments = Backend.inventory(CommandLine.arguments[index + 1])
    p.standardOutput = pipe
    p.standardError = FileHandle.standardError
    do {
        try p.run()
        let inventory = CaptureInventory()
        inventory.feed(String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self))
        inventory.finish(); p.waitUntilExit()
        guard p.terminationStatus == 0 else { exit(p.terminationStatus) }
        let report = inventory.sorted.map { InventoryReport(bssid: $0.bssid, ssid: $0.ssid, handshakeCandidate: $0.candidate, readiness: $0.readiness) }
        FileHandle.standardOutput.write(try JSONEncoder().encode(report))
    } catch { fputs("\(error.localizedDescription)\n", stderr); exit(1) }
} else if let index = CommandLine.arguments.firstIndex(of: "--test-preview") {
    guard CommandLine.arguments.count > index + 1 else { exit(2) }
    let p = Process()
    p.executableURL = URL(fileURLWithPath: Backend.tshark)
    p.arguments = Backend.preview(CommandLine.arguments[index + 1], filter: "eapol")
    p.standardOutput = FileHandle.standardOutput
    p.standardError = FileHandle.standardError
    do { try p.run(); p.waitUntilExit(); exit(p.terminationStatus) }
    catch { fputs("\(error.localizedDescription)\n", stderr); exit(1) }
} else if CommandLine.arguments.contains("--self-test") {
    precondition(Backend.bssid("02:AA:bb:01:02:03") == "02:aa:bb:01:02:03")
    precondition(Backend.bssid("aa:bb:cc:dd:ee:ff; touch /tmp/no") == nil)
    precondition(Backend.bssid("") == nil)
    let args = Backend.crack("/tmp/capture space.pcap", words: "/tmp/word list.txt", target: "02:aa:bb:01:02:03")
    precondition(args.last == "/tmp/capture space.pcap" && args.contains("/tmp/word list.txt"))
    print("Validation and process argument checks passed")
} else {
    let app = NSApplication.shared
    let delegate = PacketVault()
    let menu = NSMenu(), applicationItem = NSMenuItem(), applicationMenu = NSMenu()
    menu.addItem(applicationItem)
    applicationItem.submenu = applicationMenu
    let quit = NSMenuItem(title: "Quit Packet Vault", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    quit.target = app
    applicationMenu.addItem(quit)
    app.mainMenu = menu
    app.delegate = delegate
    app.setActivationPolicy(.regular)
    app.run()
}
