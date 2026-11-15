//
//  WQPinnedSession.swift
//  WQ Files
//
//  移植自 3105/ThreeOneOSFive/helpers/SSLPinning.swift。
//  差异：去掉 DebugLogWriter / ProtocolLogReporter 依赖，日志写 NSLog 和
//  Documents/wq-collect.log（与 WQCollector 共用同一个文件）。
//
//  只信任 SPKI-SHA256 命中的服务端叶子证书；中间 CA / Root 仅记日志。
//  fail-closed：白名单外的 HTTPS 域名一律拒绝连接。
//

import Foundation
import Security
import CryptoKit

final class WQPinnedSession {

    static let shared = WQPinnedSession()

    /// 叶子证书 SPKI-SHA256（base64）。与 3105 保持一致。
    static let leafPins: Set<String> = [
        "IaGUvNa9OwAGCTxI3GJXMYn0EWeIYkY7NI5e1vAujUw=",
        "uo7EJVlktWwqz4SokIyf1oaYcdYOSGJN5+ncEfOobKI=",
    ]

    /// 中间 CA / Root 的公钥哈希，**默认不参与判定**，仅用于日志排障。
    static let caPins: Set<String> = [
        "brzvtCELCIZUo4sD/qPX0ccRtPsd3DY6RfmxpOU9oB4=",
        "sCkq5UWXjg+7mKu9lMhhYF5bGLsy7VI/UNW3tccdR7w=",
        "diGVwiVYbubAI3RW4hB9xU8e/CH2GnkuvVFZE8zmgzI=",
    ]

    static let allowCAFallback = false
    static let enabled = true

    /// 运行时观察到的 SPKI 哈希（域名 -> base64），排障用。
    static var observed: [String: String] = [:]

    let session: URLSession

    private init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 60
        config.timeoutIntervalForResource = 2 * 60 * 60
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpMaximumConnectionsPerHost = 4
        session = URLSession(configuration: config, delegate: WQPinDelegate(), delegateQueue: nil)
    }

    static func hostKey() -> String { WQV2.hostname }

    static func enabled(for host: String) -> Bool {
        guard enabled else { return false }
        return host == hostKey()
    }

    /// 结果同时进 NSLog 和 Documents/wq-collect.log。
    static func pinLog(_ text: String) {
        NSLog("[pin] %@", text)
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        let url = dir.appendingPathComponent("wq-collect.log")
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "MM-dd HH:mm:ss.SSS"
        let line = "\(formatter.string(from: Date())) [pin] \(text)\n"
        // 同 WQNet：避开 String.data(using:)，旧系统没有那个符号。
        let data = Data(line.utf8)
        if let handle = try? FileHandle(forWritingTo: url) {
            handle.seekToEndOfFile()
            handle.write(data)
            try? handle.close()
        } else {
            try? data.write(to: url, options: .atomic)
        }
    }
}

private final class WQPinDelegate: NSObject, URLSessionDelegate {

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        let host = challenge.protectionSpace.host
        let chain = Self.spkiHashes(trust)
        let leaf = chain.first ?? ""
        if !leaf.isEmpty {
            WQPinnedSession.observed[host] = leaf
        }

        let expectedHost = WQPinnedSession.hostKey()
        let leafMatched = WQPinnedSession.leafPins.contains(leaf)
        let caMatched = chain.contains { WQPinnedSession.caPins.contains($0) }
        let accepted = leafMatched || (WQPinnedSession.allowCAFallback && caMatched)

        WQPinnedSession.pinLog(
            "\(host) chain=\(chain.count) leaf=\(leafMatched ? "YES" : "NO") "
            + "ca=\(caMatched ? "YES" : "NO") 结果=\(accepted ? "ALLOW" : "DENY") "
            + "leafHash=\(leaf)"
        )

        guard WQPinnedSession.enabled else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        guard host == expectedHost else {
            WQPinnedSession.pinLog("未在白名单的 HTTPS 域名，拒绝连接: \(host)（期望 \(expectedHost)）")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard accepted else {
            WQPinnedSession.pinLog("证书公钥不在固定集合内，拒绝连接: \(host)")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    private static func spkiHashes(_ trust: SecTrust) -> [String] {
        var chain: [SecCertificate] = []
        if #available(iOS 15.0, *) {
            chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        }
        if chain.isEmpty, let leaf = SecTrustGetCertificateAtIndex(trust, 0) {
            chain = [leaf]
        }
        var out: [String] = []
        for cert in chain {
            guard let key = SecCertificateCopyKey(cert),
                  let raw = SecKeyCopyExternalRepresentation(key, nil) as? Data else { continue }
            out.append(Data(SHA256.hash(data: Self.spkiWrap(raw, key: key))).base64EncodedString())
        }
        return out
    }

    private static func spkiWrap(_ raw: Data, key: SecKey) -> Data {
        let attrs = SecKeyCopyAttributes(key) as? [String: Any]
        let type = (attrs?[kSecAttrKeyType as String] as? String) ?? ""
        let size = (attrs?[kSecAttrKeySizeInBits as String] as? Int) ?? 256

        if type == (kSecAttrKeyTypeRSA as String) {
            let alg: [UInt8] = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                                0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]
            return derWrap(raw, algorithm: Data(alg))
        }

        let alg: [UInt8]
        if size == 384 {
            alg = [0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                   0x07, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]
        } else {
            alg = [0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                   0x07, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        }
        return derWrap(raw, algorithm: Data(alg))
    }

    private static func derWrap(_ keyBits: Data, algorithm: Data) -> Data {
        var bitString = Data([0x03])
        bitString.append(contentsOf: derLength(keyBits.count + 1))
        bitString.append(0x00)
        bitString.append(keyBits)

        var body = Data()
        body.append(algorithm)
        body.append(bitString)

        var out = Data([0x30])
        out.append(contentsOf: derLength(body.count))
        out.append(body)
        return out
    }

    private static func derLength(_ n: Int) -> [UInt8] {
        if n < 0x80 { return [UInt8(n)] }
        if n <= 0xFF { return [0x81, UInt8(n)] }
        return [0x82, UInt8((n >> 8) & 0xFF), UInt8(n & 0xFF)]
    }
}
