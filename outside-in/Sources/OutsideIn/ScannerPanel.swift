import SwiftUI

struct ScannerPanel: View {
    @EnvironmentObject var store: CaseStore
    var item: Investigation
    @ViewState private var target = ""
    @ViewState private var modules: Set<ScannerModule> = []
    private var normalized: String? { TargetInput.normalize(target) }
    private var valid: Bool { normalized.map { item.allowsScan($0) } ?? false }
    private var selected: Set<ScannerModule> { Set(modules.filter { $0.supports(normalized ?? target) }) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("COLLECTION ENGINE").font(.system(size: 11, weight: .semibold, design: .monospaced)).tracking(2).foregroundStyle(Theme.mint)
                        Text("Turn a target into evidence.").font(.system(size: 24, weight: .semibold))
                        Text("Domain and IP intelligence, with a source trail for every result.").font(.system(size: 12)).foregroundStyle(Theme.muted)
                    }
                    Spacer()
                    Image(systemName: "scope").font(.system(size: 42, weight: .ultraLight)).foregroundStyle(Theme.mint)
                }
                HStack {
                    TextField("Domain, IPv4 or IPv6 address", text: $target).textFieldStyle(.roundedBorder).font(.system(size: 14, design: .monospaced))
                    Menu("Use case asset") {
                        ForEach(item.assets.filter { [.domain, .address].contains($0.kind) && item.allowsScan($0.value) }) { asset in
                            Button(asset.value) { target = asset.value; modules = ScannerModule.defaults(for: asset.value) }
                        }
                    }.fixedSize()
                }
                if !valid && !target.isEmpty { Text("Choose a target inside this case, or create a new case for another domain/IP.").font(.system(size: 11)).foregroundStyle(.orange) }
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 12) {
                    ForEach(ScannerModule.allCases) { module in
                        let supported = module.supports(normalized ?? target)
                        Button {
                            if modules.contains(module) { modules.remove(module) } else { modules.insert(module) }
                        } label: {
                            HStack(alignment: .top, spacing: 12) {
                                Image(systemName: module.icon).font(.system(size: 21)).foregroundStyle(Theme.mint).frame(width: 28)
                                VStack(alignment: .leading, spacing: 7) {
                                    Text(module.title).font(.system(size: 13, weight: .semibold)).foregroundStyle(.primary)
                                    Text(module.detail).font(.system(size: 11)).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                                    if !supported { Text(module == .reverseDNS ? "IP addresses only" : "Domains only").font(.system(size: 10)).foregroundStyle(.orange) }
                                }
                                Spacer(minLength: 0)
                                Image(systemName: modules.contains(module) && supported ? "checkmark.circle.fill" : "circle").foregroundStyle(modules.contains(module) && supported ? Theme.mint : Theme.muted)
                            }.padding(16).frame(maxWidth: .infinity, minHeight: 95, alignment: .topLeading)
                                .background(Theme.panel, in: RoundedRectangle(cornerRadius: 10))
                                .overlay(RoundedRectangle(cornerRadius: 10).stroke(modules.contains(module) && supported ? Theme.mint.opacity(0.5) : Theme.border))
                                .opacity(supported ? 1 : 0.4)
                        }.buttonStyle(.plain).disabled(!supported || store.isCollecting)
                    }
                }
                HStack {
                    Button {
                        Task { await store.scan(target: target, modules: selected) }
                    } label: { Label(store.isCollecting ? "Collecting…" : "Run selected scanners", systemImage: "play.fill").padding(.vertical, 4) }
                        .buttonStyle(.borderedProminent).disabled(!valid || selected.isEmpty || item.isDemo || store.isCollecting)
                    Text("\(selected.count) modules selected").font(.system(size: 11, design: .monospaced)).foregroundStyle(Theme.muted)
                    Spacer()
                }
                if store.scanTotal > 0 { ProgressView(value: Double(store.scanCompleted), total: Double(store.scanTotal)).tint(Theme.mint) }
                Text(store.scanStatus).font(.system(size: 12)).foregroundStyle(Theme.muted).textSelection(.enabled)
                Divider()
                Text("DNS / PTR queries go to Cloudflare. Registration queries go through RDAP.org to the registry. Certificate searches go to crt.sh, or Cert Spotter if unavailable. HTTPS and TCP checks contact the selected target directly.").font(.system(size: 11)).foregroundStyle(Theme.muted).fixedSize(horizontal: false, vertical: true)
                if item.isDemo { Text("Create a real domain or IP case to run collectors. This training case stays synthetic.").font(.system(size: 12)).foregroundStyle(.orange) }
            }.padding(26)
        }
        .onAppear { resetTarget() }
        .onChange(of: item.id) { _, _ in resetTarget() }
        .onChange(of: normalized) { _, newValue in modules = ScannerModule.defaults(for: newValue ?? target) }
    }

    private func resetTarget() {
        let asset = item.assets.first { $0.id == store.selectedAsset && item.allowsScan($0.value) }
        target = asset?.value ?? item.scope
        modules = ScannerModule.defaults(for: target)
    }
}
