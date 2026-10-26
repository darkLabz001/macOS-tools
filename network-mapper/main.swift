import AppKit
import Foundation
import UniformTypeIdentifiers

final class MapperApp: NSObject, NSApplicationDelegate, NSTableViewDataSource, NSTableViewDelegate, NSTextFieldDelegate {
    let home = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/macOS-tools/NetworkMapper/scans", isDirectory: true)
    var window: NSWindow!
    let targets = NSTextField(string: ""), ports = NSTextField(string: ""), exclude = NSTextField(string: "")
    let top = NSTextField(string: "100"), maxRate = NSTextField(string: ""), timeout = NSTextField(string: "120")
    let scriptArgs = NSTextField(string: ""), decoys = NSTextField(string: ""), sourcePort = NSTextField(string: "")
    let spoofMAC = NSTextField(string: ""), interface = NSTextField(string: "")
    let profile = NSPopUpButton(), timing = NSPopUpButton(), scripts = NSPopUpButton(), history = NSPopUpButton()
    let versions = NSButton(checkboxWithTitle: "Service versions (-sV)", target: nil, action: nil)
    let os = NSButton(checkboxWithTitle: "OS fingerprint (-O) · sudo", target: nil, action: nil)
    let aggressive = NSButton(checkboxWithTitle: "Aggressive suite (-A) · sudo", target: nil, action: nil)
    let skip = NSButton(checkboxWithTitle: "Skip discovery (-Pn)", target: nil, action: nil)
    let trace = NSButton(checkboxWithTitle: "Traceroute · sudo", target: nil, action: nil)
    let ipv6 = NSButton(checkboxWithTitle: "IPv6 (-6)", target: nil, action: nil)
    let fragment = NSButton(checkboxWithTitle: "Fragment packets (-f) · sudo", target: nil, action: nil)
    let preview = NSTextView(), log = NSTextView(), details = NSTextView(), changes = NSTextView()
    let tabs = NSTabView(), table = NSTableView()
    let status = NSTextField(labelWithString: "IDLE · No scan starts automatically")
    var start: NSButton!, stop: NSButton!
    var controls: [NSControl] = []
    var snapshot: Snapshot?
    var saved: [URL] = []
    var directory: URL?
    var timer: Timer?
    var helper: Process?
    var lastLogSize: UInt64 = 0
    var scanIsRunning = false
    let vaultStatus = NSTextField(labelWithString: "Vault · connecting")
    let cyan = NSColor(calibratedRed: 0.2, green: 0.9, blue: 1, alpha: 1)

    func applicationDidFinishLaunching(_ notification: Notification) {
        try? FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        NSApp.appearance = NSAppearance(named: .darkAqua)
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1320, height: 920), styleMask: [.titled, .closable, .resizable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "Network Mapper"; window.minSize = NSSize(width: 1120, height: 780); window.center()
        let root = NSStackView(); root.orientation = .vertical; root.alignment = .leading; root.spacing = 12
        root.edgeInsets = NSEdgeInsets(top: 20, left: 20, bottom: 20, right: 20); root.translatesAutoresizingMaskIntoConstraints = false
        let content = window.contentView!; content.wantsLayer = true; content.layer?.backgroundColor = NSColor(calibratedWhite: 0.035, alpha: 1).cgColor
        content.addSubview(root)
        NSLayoutConstraint.activate([root.leadingAnchor.constraint(equalTo: content.leadingAnchor), root.trailingAnchor.constraint(equalTo: content.trailingAnchor), root.topAnchor.constraint(equalTo: content.topAnchor), root.bottomAnchor.constraint(equalTo: content.bottomAnchor)])
        let title = NSTextField(labelWithString: "NETWORK MAPPER  //  RECON CONSOLE")
        title.font = .monospacedSystemFont(ofSize: 25, weight: .bold); title.textColor = cyan
        root.addArrangedSubview(title)
        let info = NSTextField(labelWithString: "Explicit targets • Manual start/stop • Saved scan history • Host and service comparisons")
        info.textColor = .secondaryLabelColor; root.addArrangedSubview(info)
        vaultStatus.textColor = .secondaryLabelColor; root.addArrangedSubview(vaultStatus)
        VaultRelay.start { [weak self] in self?.vaultStatus.stringValue = $0 }
        start = button("Start scan", #selector(startScan)); start.contentTintColor = cyan
        stop = button("Stop scan", #selector(stopScan)); stop.contentTintColor = .systemRed; stop.isEnabled = false
        root.addArrangedSubview(line([start, stop, status]))
        let main = NSStackView(); main.orientation = .horizontal; main.alignment = .top; main.spacing = 18
        root.addArrangedSubview(main)
        main.widthAnchor.constraint(equalTo: root.widthAnchor, constant: -40).isActive = true
        let settingsScroll = NSScrollView(); settingsScroll.hasVerticalScroller = true; settingsScroll.drawsBackground = false
        settingsScroll.widthAnchor.constraint(equalToConstant: 390).isActive = true
        let settings = NSStackView(); settings.orientation = .vertical; settings.alignment = .leading; settings.spacing = 9
        settings.translatesAutoresizingMaskIntoConstraints = false; settingsScroll.documentView = settings
        NSLayoutConstraint.activate([settings.leadingAnchor.constraint(equalTo: settingsScroll.contentView.leadingAnchor), settings.trailingAnchor.constraint(equalTo: settingsScroll.contentView.trailingAnchor), settings.topAnchor.constraint(equalTo: settingsScroll.contentView.topAnchor), settings.widthAnchor.constraint(equalTo: settingsScroll.widthAnchor, constant: -16)])
        profile.addItems(withTitles: ScanConfig.profiles); profile.selectItem(withTitle: "TCP connect")
        timing.addItems(withTitles: (0...5).map { "T\($0)" }); timing.selectItem(at: 3)
        scripts.addItems(withTitles: ScanConfig.scriptChoices)
        targets.placeholderString = "192.0.2.0/24 or host/IP list"
        ports.placeholderString = "Blank = top ports; e.g. 22,80,443 or 1-65535"
        exclude.placeholderString = "Optional, comma-separated networks/hosts"
        maxRate.placeholderString = "Optional packets/second ceiling"
        scriptArgs.placeholderString = "Optional NSE arguments"
        decoys.placeholderString = "Optional IPs or RND:5"
        sourcePort.placeholderString = "Optional source port"
        spoofMAC.placeholderString = "Optional MAC / vendor prefix"
        interface.placeholderString = "Optional, e.g. en0"
        settings.addArrangedSubview(heading("TARGETS & SCAN"))
        for (name, control) in [("Targets", targets as NSControl), ("Profile", profile), ("Ports", ports), ("Top-port count", top), ("Timing", timing), ("Exclude", exclude)] { addSetting(name, control, to: settings) }
        for b in [versions, os, aggressive, skip, trace, ipv6] { checkbox(b, in: settings) }
        settings.addArrangedSubview(heading("ADVANCED / OFFENSIVE"))
        let caution = NSTextField(wrappingLabelWithString: "NSE vuln/auth/intrusive/brute/exploit categories actively test services and may change or disrupt them. Select these only for your assessment scope.")
        caution.font = .systemFont(ofSize: 11); caution.textColor = .secondaryLabelColor
        caution.widthAnchor.constraint(lessThanOrEqualToConstant: 360).isActive = true; settings.addArrangedSubview(caution)
        for (name, control) in [("NSE category", scripts as NSControl), ("NSE arguments", scriptArgs), ("Max rate", maxRate), ("Host timeout (seconds)", timeout)] { addSetting(name, control, to: settings) }
        checkbox(fragment, in: settings)
        for (name, control) in [("Decoys (-D)", decoys), ("Source port", sourcePort), ("Spoof MAC", spoofMAC), ("Interface", interface)] { addSetting(name, control, to: settings) }
        let rootNote = NSTextField(wrappingLabelWithString: "Root-required modes open Terminal for sudo. Passwords are never saved. Stop scan signals the privileged worker too.")
        rootNote.font = .systemFont(ofSize: 11); rootNote.textColor = .secondaryLabelColor; rootNote.widthAnchor.constraint(lessThanOrEqualToConstant: 360).isActive = true
        settings.addArrangedSubview(rootNote)
        let right = NSStackView(); right.orientation = .vertical; right.alignment = .leading; right.spacing = 10
        main.addArrangedSubview(settingsScroll); main.addArrangedSubview(right)
        settingsScroll.heightAnchor.constraint(equalTo: main.heightAnchor).isActive = true
        right.widthAnchor.constraint(equalTo: main.widthAnchor, constant: -408).isActive = true
        right.heightAnchor.constraint(equalTo: main.heightAnchor).isActive = true
        right.addArrangedSubview(heading("COMMAND PREVIEW"))
        let previewScroll = textScroll(preview); previewScroll.heightAnchor.constraint(equalToConstant: 100).isActive = true
        right.addArrangedSubview(previewScroll); previewScroll.widthAnchor.constraint(equalTo: right.widthAnchor).isActive = true
        right.addArrangedSubview(line([button("Copy command", #selector(copyCommand)), button("Open saved scans", #selector(openSaved)), button("Import Nmap XML…", #selector(importXML))]))
        history.widthAnchor.constraint(equalToConstant: 330).isActive = true
        right.addArrangedSubview(line([history, button("Load", #selector(loadHistory)), button("Compare", #selector(compareHistory))]))
        let hostScroll = NSScrollView(); hostScroll.hasVerticalScroller = true; hostScroll.hasHorizontalScroller = true
        for (id, label, width) in [("address", "Host", 150.0), ("state", "State", 70.0), ("ports", "Open ports", 180.0), ("services", "Services", 240.0), ("os", "OS guess", 240.0)] {
            let col = NSTableColumn(identifier: NSUserInterfaceItemIdentifier(id)); col.title = label; col.width = width; table.addTableColumn(col)
        }
        table.dataSource = self; table.delegate = self; table.usesAlternatingRowBackgroundColors = true
        table.target = self; table.doubleAction = #selector(showHostDetails)
        hostScroll.documentView = table
        for (name, view) in [("Hosts", hostScroll as NSView), ("Details", textScroll(details)), ("Live log", textScroll(log)), ("Changes", textScroll(changes))] {
            let tab = NSTabViewItem(identifier: name); tab.label = name; tab.view = view; tabs.addTabViewItem(tab)
        }
        right.addArrangedSubview(tabs)
        tabs.widthAnchor.constraint(equalTo: right.widthAnchor).isActive = true
        tabs.heightAnchor.constraint(greaterThanOrEqualToConstant: 300).isActive = true
        status.font = .monospacedSystemFont(ofSize: 12, weight: .medium); status.textColor = cyan
        log.string = "Ready. Select targets and options, review the command, then click Start scan.\nNo scan has been started.\n"
        details.string = "Select a host in the Hosts table, then open Details (or double-click the host)."
        changes.string = "After a scan, choose an earlier snapshot from history and click Compare.\nUse matching target scopes and port profiles: absence from a different scan does not prove a service closed."
        history.target = self; controls.append(history)
        refreshHistory(); updatePreview()
        window.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    func heading(_ text: String) -> NSTextField {
        let label = NSTextField(labelWithString: text); label.font = .monospacedSystemFont(ofSize: 12, weight: .bold); label.textColor = cyan; return label
    }
    func line(_ views: [NSView]) -> NSStackView { let stack = NSStackView(views: views); stack.spacing = 9; return stack }
    func button(_ title: String, _ action: Selector) -> NSButton { let b = NSButton(title: title, target: self, action: action); b.bezelStyle = .rounded; controls.append(b); return b }
    func checkbox(_ b: NSButton, in stack: NSStackView) { b.target = self; b.action = #selector(configChanged); controls.append(b); stack.addArrangedSubview(b) }
    func addSetting(_ label: String, _ control: NSControl, to stack: NSStackView) {
        let caption = NSTextField(labelWithString: label); caption.textColor = .secondaryLabelColor; caption.font = .systemFont(ofSize: 11)
        stack.addArrangedSubview(caption); stack.addArrangedSubview(control)
        control.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true; controls.append(control)
        if let field = control as? NSTextField { field.delegate = self }
        else { control.target = self; control.action = #selector(configChanged) }
    }
    func textScroll(_ view: NSTextView) -> NSScrollView {
        let scroll = NSScrollView(); scroll.hasVerticalScroller = true; scroll.hasHorizontalScroller = true
        view.isEditable = false; view.isSelectable = true; view.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        view.backgroundColor = NSColor(calibratedWhite: 0.025, alpha: 1); view.textColor = NSColor(calibratedWhite: 0.85, alpha: 1)
        view.isHorizontallyResizable = true; view.textContainer?.widthTracksTextView = false
        view.textContainer?.containerSize = NSSize(width: 100000, height: 10000000); view.textContainerInset = NSSize(width: 10, height: 10)
        scroll.documentView = view; return scroll
    }
    func config() -> ScanConfig {
        var c = ScanConfig()
        c.targets = targets.stringValue; c.profile = profile.titleOfSelectedItem ?? "TCP connect"; c.ports = ports.stringValue.trimmingCharacters(in: .whitespaces)
        c.topPorts = Int(top.stringValue) ?? 0; c.timing = timing.indexOfSelectedItem
        c.versions = versions.state == .on; c.os = os.state == .on; c.aggressive = aggressive.state == .on
        c.skipDiscovery = skip.state == .on; c.traceroute = trace.state == .on; c.ipv6 = ipv6.state == .on
        c.scripts = scripts.titleOfSelectedItem ?? "None"; c.scriptArgs = scriptArgs.stringValue
        c.excludes = exclude.stringValue; c.maxRate = maxRate.stringValue; c.hostTimeout = timeout.stringValue
        c.fragment = fragment.state == .on; c.decoys = decoys.stringValue; c.sourcePort = sourcePort.stringValue; c.spoofMAC = spoofMAC.stringValue; c.networkInterface = interface.stringValue
        return c
    }
    func command() throws -> String {
        let c = config(); var args = try c.arguments(output: "managed-output")
        if let index = args.firstIndex(of: "-oA") { args.removeSubrange(index...index+1) }
        return (c.needsRoot ? "sudo " : "") + (["/opt/homebrew/bin/nmap"] + args).map(shellQuote).joined(separator: " ")
    }
    @objc func configChanged() { updatePreview() }
    func controlTextDidChange(_ notification: Notification) { updatePreview() }
    func updatePreview() { do { preview.string = try command() } catch { preview.string = error.localizedDescription } }
    @objc func copyCommand() { do { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(try command(), forType: .string) } catch { alert(error.localizedDescription) } }
    func alert(_ text: String) { let a = NSAlert(); a.messageText = text; a.beginSheetModal(for: window) }
    func busy(_ value: Bool) { scanIsRunning = value; for c in controls { c.isEnabled = !value }; stop.isEnabled = value }
    @objc func startScan() {
        guard !scanIsRunning else { return }
        do {
            let c = config(); try c.validate()
            let dir = home.appendingPathComponent("\(Int(Date().timeIntervalSince1970))-\(UUID().uuidString.prefix(8))", isDirectory: true)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try writeJSON(c, dir.appendingPathComponent("config.json"))
            directory = dir; lastLogSize = 0; log.string = "Preparing scan…\n"; busy(true); tabs.selectTabViewItem(at: 2)
            if c.needsRoot {
                let script = dir.appendingPathComponent("authorize.command")
                let body = "#!/bin/zsh\n/usr/bin/sudo " + shellQuote(Bundle.main.executablePath!) + " --worker " + shellQuote(dir.path) + "\n"
                try body.write(to: script, atomically: true, encoding: .utf8)
                try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
                status.stringValue = "WAITING · Complete sudo authorization in Terminal"
                NSWorkspace.shared.open([script], withApplicationAt: URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app"), configuration: NSWorkspace.OpenConfiguration()) { _, error in
                    if let error { try? writeJSON(WorkerStatus(exitCode: 1, stopped: false, error: error.localizedDescription), dir.appendingPathComponent("status.json")) }
                }
            } else {
                let p = Process(); p.executableURL = Bundle.main.executableURL; p.arguments = ["--worker", dir.path]
                p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
                try p.run(); helper = p; status.stringValue = "RUNNING · \(c.targets)"
            }
            timer = Timer.scheduledTimer(withTimeInterval: 0.4, repeats: true) { _ in self.poll() }
        } catch { busy(false); alert(error.localizedDescription) }
    }
    func poll() {
        guard let dir = directory else { return }
        let path = dir.appendingPathComponent("console.log")
        if let handle = try? FileHandle(forReadingFrom: path) {
            defer { try? handle.close() }
            if let size = try? handle.seekToEnd(), size != lastLogSize {
                lastLogSize = size; try? handle.seek(toOffset: size > 524288 ? size - 524288 : 0)
                if let bytes = try? handle.readToEnd() { log.string = String(decoding: bytes, as: UTF8.self); log.scrollToEndOfDocument(nil) }
            }
        }
        let statusPath = dir.appendingPathComponent("status.json")
        guard let bytes = try? Data(contentsOf: statusPath), let result = try? JSONDecoder().decode(WorkerStatus.self, from: bytes) else {
            if FileManager.default.fileExists(atPath: dir.appendingPathComponent("STARTED").path) { status.stringValue = "RUNNING · Scan active" }
            return
        }
        timer?.invalidate(); timer = nil; busy(false); helper = nil
        status.stringValue = result.stopped ? "STOPPED · Partial artifacts retained" : "FINISHED · Exit \(result.exitCode)"
        if let error = result.error { log.string += "\n\(error)\n" }
        if let data = try? Data(contentsOf: dir.appendingPathComponent("snapshot.json")), let saved = try? JSONDecoder().decode(Snapshot.self, from: data) { display(saved) }
        refreshHistory()
    }
    @objc func stopScan() {
        guard scanIsRunning, let dir = directory else { return }
        do {
            try Data().write(to: dir.appendingPathComponent("STOP"))
            status.stringValue = "STOPPING · Waiting for scan worker"
            if !FileManager.default.fileExists(atPath: dir.appendingPathComponent("STARTED").path) {
                try writeJSON(WorkerStatus(exitCode: 143, stopped: true), dir.appendingPathComponent("status.json"))
            }
        } catch { alert(error.localizedDescription) }
    }
    func display(_ value: Snapshot) {
        snapshot = value; table.reloadData()
        details.string = "\(value.hosts.count) hosts recorded. Select a host to inspect ports and script output."
        if let data = try? JSONEncoder().encode(value) {
            VaultRelay.submit("mapper", data: data) { [weak self] in self?.vaultStatus.stringValue = $0 }
        }
    }
    func refreshHistory() {
        saved = ((try? FileManager.default.contentsOfDirectory(at: home, includingPropertiesForKeys: nil)) ?? []).filter { FileManager.default.fileExists(atPath: $0.appendingPathComponent("snapshot.json").path) }.sorted { $0.lastPathComponent > $1.lastPathComponent }
        history.removeAllItems()
        for dir in saved {
            let config = (try? JSONDecoder().decode(ScanConfig.self, from: Data(contentsOf: dir.appendingPathComponent("config.json"))))
            history.addItem(withTitle: "\(dir.lastPathComponent) · \(config?.targets ?? "saved")")
        }
        if saved.isEmpty { history.addItem(withTitle: "No completed scans yet") }
    }
    func chosenSnapshot() throws -> Snapshot {
        guard saved.indices.contains(history.indexOfSelectedItem) else { throw MapperError.message("Choose a completed scan first.") }
        return try JSONDecoder().decode(Snapshot.self, from: Data(contentsOf: saved[history.indexOfSelectedItem].appendingPathComponent("snapshot.json")))
    }
    @objc func loadHistory() { do { let saved = try chosenSnapshot(); display(saved); status.stringValue = "LOADED · \(saved.config.targets)"; tabs.selectTabViewItem(at: 0) } catch { alert(error.localizedDescription) } }
    @objc func compareHistory() {
        do {
            guard let snapshot else { throw MapperError.message("Run or load the current scan first.") }
            let baseline = try chosenSnapshot()
            changes.string = "BASELINE: \(baseline.config.targets) / \(baseline.config.profile)\nCURRENT: \(snapshot.config.targets) / \(snapshot.config.profile)\n\nDifferent scopes or port selections can produce apparent changes.\n\n" + compare(baseline.hosts, snapshot.hosts)
            tabs.selectTabViewItem(at: 3)
        } catch { alert(error.localizedDescription) }
    }
    @objc func importXML() {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.xml]; panel.canChooseDirectories = false
        panel.beginSheetModal(for: window) { response in
            guard response == .OK, let url = panel.url else { return }
            do { var c = ScanConfig(); c.targets = url.lastPathComponent; self.display(Snapshot(date: Date(), config: c, hosts: try NmapXML.read(Data(contentsOf: url)))); self.status.stringValue = "IMPORTED · \(url.lastPathComponent) · No scan started"; self.tabs.selectTabViewItem(at: 0) }
            catch { self.alert(error.localizedDescription) }
        }
    }
    @objc func openSaved() { NSWorkspace.shared.open(home) }
    func numberOfRows(in tableView: NSTableView) -> Int { snapshot?.hosts.count ?? 0 }
    func tableView(_ tableView: NSTableView, objectValueFor tableColumn: NSTableColumn?, row: Int) -> Any? {
        guard let hosts = snapshot?.hosts, hosts.indices.contains(row) else { return nil }
        let h = hosts[row]
        switch tableColumn?.identifier.rawValue {
        case "address": return h.address + (h.name.isEmpty ? "" : " (\(h.name))")
        case "state": return h.state
        case "ports": return h.ports.filter { $0.state == "open" }.map { $0.key }.joined(separator: ", ")
        case "services": return h.ports.filter { $0.state == "open" }.map { "\($0.service) \($0.version)" }.joined(separator: "; ")
        case "os": return h.os
        default: return ""
        }
    }
    func tableViewSelectionDidChange(_ notification: Notification) {
        guard let hosts = snapshot?.hosts, hosts.indices.contains(table.selectedRow) else { return }
        let h = hosts[table.selectedRow]
        details.string = "HOST \(h.address) \(h.name)\nSTATE \(h.state)\nOS \(h.os.isEmpty ? "Not detected" : h.os)\n\n" + h.ports.map { "\($0.key)  \($0.state)  \($0.service)  \($0.version)\n" + $0.scripts.joined(separator: "\n") }.joined(separator: "\n") + "\n\nHOST SCRIPTS\n" + h.scripts.joined(separator: "\n")
    }
    @objc func showHostDetails() { tabs.selectTabViewItem(at: 1) }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationWillTerminate(_ notification: Notification) { if scanIsRunning, let directory { try? Data().write(to: directory.appendingPathComponent("STOP")) } }
}

let args = CommandLine.arguments
if let index = args.firstIndex(of: "--worker"), args.count > index + 1 { exit(worker(URL(fileURLWithPath: args[index + 1], isDirectory: true))) }
else if args.contains("--self-test") {
    var c = ScanConfig(); c.targets = "127.0.0.1"; c.ports = "22,80,443"; c.skipDiscovery = true
    let a = try c.arguments(output: "/tmp/mapper fixture")
    precondition(a.contains("-sT") && a.contains("-Pn") && !a.contains("--script"))
    c.targets = "127.0.0.1;touch /tmp/no"
    precondition((try? c.validate()) == nil)
    c.targets = "--script=all"; precondition((try? c.validate()) == nil)
    c.targets = "127.0.0.1"; c.profile = "TCP SYN"; c.scripts = "vuln"; c.fragment = true
    let advanced = try c.arguments(output: "/tmp/test")
    precondition(c.needsRoot && advanced.contains("-f"))
    let xml = "<nmaprun><host><status state='up'/><address addr='127.0.0.1' addrtype='ipv4'/><ports><port protocol='tcp' portid='443'><state state='open'/><service name='https' product='Fixture' version='1'/><script id='fixture' output='test output'/></port></ports></host></nmaprun>"
    let hosts = try NmapXML.read(Data(xml.utf8)); precondition(hosts.count == 1 && hosts[0].ports[0].scripts == ["fixture: test output"])
    var changed = hosts; changed[0].ports[0].state = "closed"
    precondition(compare(hosts, changed).contains("open") && compare(hosts, changed).contains("closed"))
    print("PASS: target validation, manual defaults, advanced flags, XML parsing, and scan comparisons")
} else if let index = args.firstIndex(of: "--write-test-config"), args.count > index + 2 {
    var c = ScanConfig(); c.targets = "127.0.0.1"; c.ports = args[index + 2]; c.skipDiscovery = true
    try writeJSON(c, URL(fileURLWithPath: args[index + 1]))
} else {
    let app = NSApplication.shared, delegate = MapperApp()
    app.delegate = delegate; app.setActivationPolicy(.regular); app.run()
}
