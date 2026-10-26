import SwiftUI

// Name the property-wrapper type explicitly for Command Line Tools SDKs
// that declare the newer State macro without shipping its compiler plugin.
typealias ViewState<Value> = SwiftUI.State<Value>

@main struct OutsideInApp: App {
    @StateObject private var store = CaseStore()
    init() { NSApplication.shared.applicationIconImage = Theme.appIcon }
    var body: some Scene {
        WindowGroup {
            WorkspaceView().environmentObject(store)
                .preferredColorScheme(.dark)
                .frame(minWidth: 1120, minHeight: 740)
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) {}
            CommandMenu("Investigation") {
                Button("Export Markdown Report") { store.export(json: false) }.keyboardShortcut("e", modifiers: [.command, .shift])
                Button("Export Case JSON") { store.export(json: true) }
            }
        }
    }
}

enum Theme {
    static var appIcon: NSImage {
        if let url = Bundle.main.url(forResource: "OutsideIn", withExtension: "icns"), let image = NSImage(contentsOf: url) { return image }
        return NSImage(named: NSImage.applicationIconName) ?? NSImage()
    }
    static let background = Color(red: 0.035, green: 0.049, blue: 0.066)
    static let panel = Color(red: 0.063, green: 0.081, blue: 0.102)
    static let mint = Color(red: 0.38, green: 0.94, blue: 0.76)
    static let muted = Color(red: 0.54, green: 0.60, blue: 0.66)
    static let border = Color.white.opacity(0.09)
}

enum WorkspaceTab: String, CaseIterable { case graph = "Asset graph", scanners = "Scanners", evidence = "Evidence", leads = "Investigation gaps", log = "Collection log" }

struct WorkspaceView: View {
    @EnvironmentObject var store: CaseStore
    @ViewState private var tab: WorkspaceTab = .graph
    @ViewState private var newCase = false
    @ViewState private var addEvidence = false
    @ViewState private var search = ""

    var body: some View {
        HStack(spacing: 0) {
            sidebar.frame(width: 220)
            Rectangle().fill(Theme.border).frame(width: 1)
            VStack(spacing: 0) {
                header
                if let item = store.current {
                    HStack(spacing: 20) {
                        metric("ASSETS", value: item.assets.count)
                        metric("EVIDENCE", value: item.evidence.count)
                        metric("OPEN LEADS", value: item.leads.count)
                        Spacer()
                        if item.isDemo { Label("SYNTHETIC TRAINING DATA", systemImage: "flask").font(.system(size: 10, weight: .semibold, design: .monospaced)).foregroundStyle(.orange) }
                    }.padding(20)
                    HStack(spacing: 6) {
                        ForEach(WorkspaceTab.allCases, id: \.self) { value in
                            Button { tab = value } label: {
                                Text(value.rawValue).font(.system(size: 12, weight: .medium)).padding(.horizontal, 13).padding(.vertical, 9)
                                    .background(tab == value ? Theme.mint.opacity(0.12) : .clear, in: RoundedRectangle(cornerRadius: 7))
                                    .foregroundStyle(tab == value ? Theme.mint : Theme.muted)
                            }.buttonStyle(.plain)
                        }
                        Spacer()
                        TextField("Filter assets…", text: $search).textFieldStyle(.roundedBorder).frame(width: 160)
                    }.padding(.horizontal, 20).padding(.bottom, 14)
                    Divider().overlay(Theme.border)
                    HStack(spacing: 0) {
                        Group {
                            switch tab {
                            case .graph: GraphView(item: item, filter: search)
                            case .scanners: ScannerPanel(item: item)
                            case .evidence: evidenceList(item)
                            case .leads: leadList(item)
                            case .log: logList(item)
                            }
                        }.frame(maxWidth: .infinity, maxHeight: .infinity)
                        if tab != .scanners, let selected = item.assets.first(where: { $0.id == store.selectedAsset }) {
                            Rectangle().fill(Theme.border).frame(width: 1)
                            inspector(selected, in: item).frame(width: 285)
                        }
                    }
                } else {
                    ContentUnavailableView("Start an investigation", systemImage: "point.3.connected.trianglepath.dotted", description: Text("Create a case with a domain to establish your scope."))
                    Button("New investigation") { newCase = true }.buttonStyle(.borderedProminent).padding()
                    Spacer()
                }
                footer
            }
        }.background(Theme.background)
            .tint(Theme.mint)
            .sheet(isPresented: $newCase) { NewCaseView() }
            .sheet(isPresented: $addEvidence) { EvidenceForm() }
            .onChange(of: store.selection) { _, _ in store.selectedAsset = nil; search = "" }
            .alert("Outside In", isPresented: Binding(get: { store.notice != nil }, set: { if !$0 { store.notice = nil } })) {
                Button("OK") { store.notice = nil }
            } message: { Text(store.notice ?? "") }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(nsImage: Theme.appIcon).resizable().frame(width: 36, height: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text("OUTSIDE IN").font(.system(size: 15, weight: .bold, design: .monospaced))
                    Text("FOLLOW THE EVIDENCE").font(.system(size: 8, design: .monospaced)).foregroundStyle(Theme.muted)
                }
            }.padding(.top, 40).padding(.bottom, 32)
            Text("INVESTIGATIONS").font(.system(size: 10, weight: .semibold, design: .monospaced)).foregroundStyle(Theme.muted).padding(.bottom, 14)
            ForEach(store.cases) { item in
                Button { store.selection = item.id } label: {
                    HStack(alignment: .top, spacing: 9) {
                        Image(systemName: item.isDemo ? "flask" : "folder").padding(.top, 2)
                        VStack(alignment: .leading, spacing: 5) {
                            Text(item.name).font(.system(size: 12, weight: .medium)).lineLimit(2)
                            Text(item.scope).font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.muted).lineLimit(1)
                        }
                        Spacer(minLength: 0)
                    }.padding(11).background(store.selection == item.id ? Theme.mint.opacity(0.09) : .clear, in: RoundedRectangle(cornerRadius: 8))
                }.buttonStyle(.plain).padding(.bottom, 5)
            }
            Button { newCase = true } label: { Label("New investigation", systemImage: "plus").font(.system(size: 12)).padding(.vertical, 12) }.buttonStyle(.plain).foregroundStyle(Theme.mint)
            Spacer()
            VStack(alignment: .leading, spacing: 8) {
                Label("LOCAL WORKSPACE", systemImage: "internaldrive").font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.mint)
                Text("Cases are saved locally. Optional Vault sync requires your own configuration. DNS queries go to Cloudflare.").font(.system(size: 11)).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                Text(store.vaultStatus).font(.system(size: 10)).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                Button(store.isSyncing ? "Syncing…" : "Sync Vault now") { Task { await store.syncVault() } }.disabled(store.isSyncing).font(.system(size: 11))
            }.padding(.bottom, 22)
        }.padding(.horizontal, 17).background(Theme.panel)
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 5) {
                Text("RECONNAISSANCE WORKSPACE").font(.system(size: 9, weight: .semibold, design: .monospaced)).tracking(2).foregroundStyle(Theme.muted)
                Text(store.current?.name ?? "Outside In").font(.system(size: 24, weight: .semibold))
            }
            Spacer()
            if let item = store.current {
                Menu { Button("Markdown report") { store.export(json: false) }; Button("Case JSON + raw responses") { store.export(json: true) } } label: { Label("Export", systemImage: "square.and.arrow.up") }.fixedSize()
                Button { addEvidence = true } label: { Label("Add evidence", systemImage: "plus") }
                Button { tab = .scanners } label: { Label("Scanners", systemImage: "scope") }
                Button {
                    let selected = item.assets.first { $0.id == store.selectedAsset && $0.kind == .domain && item.containsDomain($0.value) }
                    Task { await store.collect(domain: selected?.value ?? item.scope) }
                } label: {
                    HStack { if store.isCollecting { ProgressView().controlSize(.small) }; Label(store.isCollecting ? "Collecting…" : "Collect DNS", systemImage: "antenna.radiowaves.left.and.right") }
                }.buttonStyle(.borderedProminent).disabled(store.isCollecting || item.isDemo || TargetInput.ip(item.scope) != nil)
            }
        }.padding(.horizontal, 23).padding(.top, 30).padding(.bottom, 20)
    }

    private func metric(_ label: String, value: Int) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text("\(value)").font(.system(size: 24, weight: .light, design: .monospaced))
            Text(label).font(.system(size: 9, weight: .medium, design: .monospaced)).foregroundStyle(Theme.muted)
        }.padding(.trailing, 20)
    }

    private var footer: some View {
        HStack {
            Circle().fill(Theme.mint).frame(width: 5, height: 5)
            Text(store.isCollecting ? "COLLECTION IN PROGRESS" : "READY").font(.system(size: 9, design: .monospaced))
            Spacer()
            Text("Observed ≠ owned  ·  Leads require verification").font(.system(size: 10)).foregroundStyle(Theme.muted)
        }.padding(.horizontal, 20).padding(.vertical, 11).background(Theme.panel)
    }

    private func evidenceList(_ item: Investigation) -> some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 12) {
                ForEach(item.evidence.filter { evidence in search.isEmpty || (item.label(evidence.from) + item.label(evidence.to) + evidence.excerpt).localizedCaseInsensitiveContains(search) }) { evidence in
                    Button { store.selectedAsset = evidence.to } label: { EvidenceCard(item: item, evidence: evidence) }.buttonStyle(.plain)
                }
                if item.evidence.isEmpty { ContentUnavailableView("No evidence yet", systemImage: "doc.text.magnifyingglass", description: Text("Collect DNS or add a public-source clue.")) }
            }.padding(20)
        }
    }

    private func leadList(_ item: Investigation) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("SHOW ME WHAT I’M MISSING").font(.system(size: 11, weight: .medium, design: .monospaced)).tracking(2).foregroundStyle(Theme.mint)
                Text("Evidence-based next steps. These are research gaps, not vulnerability claims.").foregroundStyle(Theme.muted).font(.system(size: 12))
                ForEach(item.leads) { lead in
                    VStack(alignment: .leading, spacing: 11) {
                        Label(lead.title, systemImage: "scope").font(.system(size: 15, weight: .medium))
                        Text(lead.detail).font(.system(size: 12)).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                        Button(lead.action == .collect ? "Collect DNS baseline" : lead.action == .add ? "Add evidence" : lead.action == .scan ? "Open scanners" : "Inspect connection") {
                            store.selectedAsset = lead.assetID
                            switch lead.action {
                            case .collect:
                                if let asset = item.assets.first(where: { $0.id == lead.assetID }) { Task { await store.collect(domain: asset.value) } }
                            case .add: addEvidence = true
                            case .inspect: tab = .evidence
                            case .scan: tab = .scanners
                            }
                        }.disabled(lead.action == .collect && (item.isDemo || store.isCollecting))
                    }.padding(18).frame(maxWidth: .infinity, alignment: .leading).background(Theme.panel, in: RoundedRectangle(cornerRadius: 10))
                }
                if item.leads.isEmpty { Text("DNS baseline complete. Add another public source to broaden this investigation.").foregroundStyle(Theme.muted).padding(.top, 20) }
            }.padding(24)
        }
    }

    private func logList(_ item: Investigation) -> some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 14) {
                ForEach(item.runs.reversed()) { run in
                    VStack(alignment: .leading, spacing: 7) {
                        HStack { Text("\(run.recordType)  \(run.domain)").font(.system(size: 12, weight: .medium, design: .monospaced)); Spacer(); Text(run.capturedAt, style: .time).foregroundStyle(Theme.muted) }
                        Text(run.outcome).foregroundStyle(run.outcome.hasPrefix("Success") ? Theme.mint : .orange)
                        DisclosureGroup("Raw response") { Text(run.rawResponse.isEmpty ? "No response captured." : run.rawResponse).font(.system(size: 10, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                    }.font(.system(size: 12)).padding(16).background(Theme.panel, in: RoundedRectangle(cornerRadius: 8))
                }
                if item.runs.isEmpty { ContentUnavailableView("No collections yet", systemImage: "antenna.radiowaves.left.and.right", description: Text("Each query retains its result and raw response here.")) }
            }.padding(20)
        }
    }

    private func inspector(_ asset: Asset, in item: Investigation) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack { Text("ASSET DETAILS").font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.muted); Spacer(); Button { store.selectedAsset = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain) }
                Image(systemName: asset.kind.icon).font(.system(size: 30)).foregroundStyle(Theme.mint)
                Text(asset.value).font(.system(size: 17, weight: .medium, design: .monospaced)).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                Text(asset.kind.rawValue.uppercased()).font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.muted)
                if asset.kind == .domain || asset.kind == .nameserver || asset.kind == .mailserver {
                    Label(item.containsDomain(asset.value) ? "Inside domain scope" : "Outside domain scope", systemImage: item.containsDomain(asset.value) ? "scope" : "arrow.up.right").font(.system(size: 11)).foregroundStyle(item.containsDomain(asset.value) ? Theme.mint : .orange)
                } else { Text("Ownership is not established by a connection.").font(.system(size: 11)).foregroundStyle(Theme.muted) }
                Divider()
                Text("SOURCE TRAIL").font(.system(size: 10, design: .monospaced)).foregroundStyle(Theme.muted)
                ForEach(item.evidence.filter { $0.from == asset.id || $0.to == asset.id }) { evidence in EvidenceCard(item: item, evidence: evidence, compact: true) }
                Button { addEvidence = true } label: { Label("Attach evidence", systemImage: "plus") }
            }.padding(20)
        }.background(Theme.panel.opacity(0.55))
    }
}

struct EvidenceCard: View {
    var item: Investigation
    var evidence: Evidence
    var compact = false
    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack {
                Text(evidence.status.rawValue.uppercased()).font(.system(size: 9, weight: .semibold, design: .monospaced)).foregroundStyle(evidence.status == .observed ? Theme.mint : .orange)
                Spacer()
                Text(evidence.capturedAt, style: .date).font(.system(size: 9)).foregroundStyle(Theme.muted)
            }
            Text(evidence.relationship).font(.system(size: 13, weight: .medium))
            if !compact { Text("\(item.label(evidence.from)) → \(item.label(evidence.to))").font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.muted) }
            Text(evidence.excerpt).font(.system(size: 11)).foregroundStyle(Theme.muted).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            if let url = URL(string: evidence.source), ["https", "http"].contains(url.scheme?.lowercased() ?? "") {
                Link(destination: url) { Label("Open source", systemImage: "arrow.up.right.square").font(.system(size: 10)) }
            }
        }.padding(13).frame(maxWidth: .infinity, alignment: .leading).background(Theme.panel, in: RoundedRectangle(cornerRadius: 8)).overlay(RoundedRectangle(cornerRadius: 8).stroke(Theme.border))
    }
}

struct GraphView: View {
    @EnvironmentObject var store: CaseStore
    var item: Investigation
    var filter: String
    private var visible: [Asset] { item.assets.filter { filter.isEmpty || $0.value.localizedCaseInsensitiveContains(filter) } }

    var body: some View {
        GeometryReader { geometry in
            let assets = visible
            let expanded = assets.count > 12 ? ceil(sqrt(Double(assets.count))) * 210 : 0
            let size = CGSize(width: max(geometry.size.width, expanded), height: max(geometry.size.height, expanded))
            let points = positions(assets, size: size)
            ScrollView([.horizontal, .vertical]) {
            ZStack(alignment: .topLeading) {
                Canvas { context, canvasSize in
                    for x in stride(from: 16.0, to: canvasSize.width, by: 25) {
                        for y in stride(from: 16.0, to: canvasSize.height, by: 25) {
                            context.fill(Path(ellipseIn: CGRect(x: x, y: y, width: 1.3, height: 1.3)), with: .color(.white.opacity(0.10)))
                        }
                    }
                    for edge in item.evidence where edge.from != edge.to {
                        guard let from = points[edge.from], let to = points[edge.to] else { continue }
                        var path = Path(); path.move(to: from); path.addLine(to: to)
                        let focused = store.selectedAsset == nil || edge.from == store.selectedAsset || edge.to == store.selectedAsset
                        context.stroke(path, with: .color((edge.status == .hypothesis ? Color.orange : Theme.mint).opacity(focused ? 0.48 : 0.10)), style: StrokeStyle(lineWidth: focused ? 1.3 : 0.8, dash: edge.status == .hypothesis ? [5, 5] : []))
                        let middle = CGPoint(x: from.x * 0.42 + to.x * 0.58, y: from.y * 0.42 + to.y * 0.58)
                        let angle = atan2(to.y - from.y, to.x - from.x)
                        var arrow = Path()
                        arrow.move(to: CGPoint(x: middle.x - 6 * cos(angle - 0.5), y: middle.y - 6 * sin(angle - 0.5)))
                        arrow.addLine(to: middle)
                        arrow.addLine(to: CGPoint(x: middle.x - 6 * cos(angle + 0.5), y: middle.y - 6 * sin(angle + 0.5)))
                        context.stroke(arrow, with: .color(Theme.mint.opacity(focused ? 0.7 : 0.1)), lineWidth: 1)
                    }
                }
                ForEach(assets) { asset in
                    if let point = points[asset.id] {
                        Button { store.selectedAsset = asset.id } label: {
                            VStack(spacing: 7) {
                                Image(systemName: asset.kind.icon).font(.system(size: 20)).foregroundStyle(Theme.mint)
                                    .frame(width: 48, height: 48)
                                    .background(Theme.panel, in: RoundedRectangle(cornerRadius: 14))
                                    .overlay(RoundedRectangle(cornerRadius: 14).stroke(store.selectedAsset == asset.id ? Theme.mint : Theme.mint.opacity(0.25), lineWidth: store.selectedAsset == asset.id ? 2 : 1))
                                Text(asset.value).font(.system(size: 10, weight: .medium, design: .monospaced)).lineLimit(1).truncationMode(.middle).multilineTextAlignment(.center).frame(width: 145)
                                Text(asset.kind.rawValue.uppercased()).font(.system(size: 8, design: .monospaced)).foregroundStyle(Theme.muted)
                            }.frame(width: 150, height: 98)
                        }.buttonStyle(.plain).position(point)
                    }
                }
                VStack(alignment: .leading, spacing: 5) {
                    Text("THE EXTERNAL PICTURE").font(.system(size: 10, weight: .medium, design: .monospaced)).tracking(2)
                    Text("Select an asset to follow its source trail").font(.system(size: 11)).foregroundStyle(Theme.muted)
                }.padding(22).allowsHitTesting(false)
                VStack { Spacer(); HStack(spacing: 16) { Label("Observed", systemImage: "line.diagonal").foregroundStyle(Theme.mint); Label("Hypothesis", systemImage: "ellipsis").foregroundStyle(.orange); Spacer(); Text("\(assets.count) assets") }.font(.system(size: 10, design: .monospaced)).padding(20) }.allowsHitTesting(false)
                if assets.isEmpty { ContentUnavailableView("No matching assets", systemImage: "magnifyingglass").frame(width: size.width, height: size.height) }
            }.frame(width: size.width, height: size.height)
            }.defaultScrollAnchor(.center)
        }
    }

    private func positions(_ assets: [Asset], size: CGSize) -> [UUID: CGPoint] {
        var result: [UUID: CGPoint] = [:]
        let center = CGPoint(x: size.width / 2, y: size.height / 2 + 12)
        guard let root = assets.first else { return result }
        result[root.id] = center
        let others = Array(assets.dropFirst())
        var rings = 1
        while 5 * rings * (rings + 1) < others.count { rings += 1 }
        for (index, asset) in others.enumerated() {
            var ring = 1
            var start = 0
            while index >= start + ring * 10 { start += ring * 10; ring += 1 }
            let count = min(ring * 10, others.count - start)
            let angle = Double(index - start) / Double(max(count, 1)) * 2 * .pi - .pi / 2
            let scale = Double(ring) / Double(rings)
            let radiusX = max(90, size.width / 2 - 90) * scale
            let radiusY = max(90, size.height / 2 - 110) * scale
            result[asset.id] = CGPoint(x: center.x + cos(angle) * radiusX, y: center.y + sin(angle) * radiusY)
        }
        return result
    }
}

struct NewCaseView: View {
    @EnvironmentObject var store: CaseStore
    @Environment(\.dismiss) var dismiss
    @ViewState private var name = ""
    @ViewState private var domain = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Label("New investigation", systemImage: "viewfinder").font(.system(size: 23, weight: .semibold))
            Text("Start with a domain or IP address. Domain cases include subdomains; IP cases focus on one address.").foregroundStyle(Theme.muted)
            TextField("Case name", text: $name).textFieldStyle(.roundedBorder)
            TextField("Domain or IP · example.com / 1.1.1.1", text: $domain).textFieldStyle(.roundedBorder)
            Text("Collection queries Cloudflare’s public DNS resolver. Results and source responses are saved locally and sent to your configured OSINT Vault.").font(.system(size: 11)).foregroundStyle(Theme.muted)
            HStack { Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction); Spacer(); Button("Create investigation") { store.create(name: name, scope: domain); dismiss() }.buttonStyle(.borderedProminent).disabled(TargetInput.normalize(domain) == nil).keyboardShortcut(.defaultAction) }
        }.padding(30).frame(width: 470).background(Theme.background).tint(Theme.mint)
    }
}

struct EvidenceForm: View {
    @EnvironmentObject var store: CaseStore
    @Environment(\.dismiss) var dismiss
    @ViewState private var from: UUID?
    @ViewState private var value = ""
    @ViewState private var kind: AssetKind = .domain
    @ViewState private var relation = "mentions hostname"
    @ViewState private var source = ""
    @ViewState private var excerpt = ""
    @ViewState private var status: EvidenceStatus = .observed
    private var valid: Bool {
        guard from != nil, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !relation.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              !excerpt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let url = URL(string: source), ["https", "http"].contains(url.scheme?.lowercased() ?? ""), url.host != nil else { return false }
        if [.domain, .nameserver, .mailserver].contains(kind) { return DomainInput.normalize(value) != nil }
        return true
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Attach a source. Build a connection.").font(.system(size: 22, weight: .semibold))
            Form {
                Picker("From asset", selection: $from) { ForEach(store.current?.assets ?? []) { asset in Text(asset.value).tag(Optional(asset.id)) } }
                TextField("Connected asset", text: $value)
                Picker("Asset type", selection: $kind) { ForEach(AssetKind.allCases, id: \.self) { Text($0.rawValue.capitalized).tag($0) } }
                TextField("Relationship", text: $relation)
                TextField("Source URL", text: $source)
                Picker("Evidence status", selection: $status) { ForEach(EvidenceStatus.allCases, id: \.self) { Text($0.rawValue).tag($0) } }
                Text("Exact excerpt / observation").foregroundStyle(Theme.muted)
                TextEditor(text: $excerpt).font(.system(size: 12, design: .monospaced)).frame(height: 100).border(Theme.border)
            }.formStyle(.grouped)
            Text("Observed records what the source says. Use Hypothesis for an interpretation that still needs corroboration.").font(.system(size: 11)).foregroundStyle(Theme.muted)
            HStack { Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction); Spacer(); Button("Save evidence") {
                if let from {
                    let cleanValue = [.domain, .nameserver, .mailserver].contains(kind) ? (DomainInput.normalize(value) ?? value) : value
                    store.addEvidence(value: cleanValue, kind: kind, from: from, relation: relation, source: source, excerpt: excerpt, status: status)
                    dismiss()
                }
            }.buttonStyle(.borderedProminent).disabled(!valid).keyboardShortcut(.defaultAction) }
        }.padding(26).frame(width: 560).background(Theme.background).tint(Theme.mint)
            .onAppear { from = store.selectedAsset ?? store.current?.assets.first?.id }
    }
}
