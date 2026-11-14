//
//  WQSecrets.swift
//  WQFiles
//
//  给 ObjC 侧的桥：SecureBox 是 Swift + CryptoKit（AES-GCM），CommonCrypto 没有 GCM，
//  纯 ObjC 手写 GHASH 容易错。所以这里用 swiftc 单独编成 .o，和 ObjC 一起链接，
//  iOS 自带 Swift runtime，不需要额外嵌入 dylib。
//
//  ObjC 侧声明（见 WQSecretsBridge.h，WQCompat.h 已强制引入）：
//      extern const char *wq_secret(int32_t id);
//      extern const char *wq_secret_base_url(void);
//      extern int32_t wq_secret_aes_material(int32_t pair, ...);
//
//  四组 key/iv 的对应关系（id 与 GeneratedSecrets.ID 一致，来源 3105/tools/secrets.json）：
//
//      pair 0  links     13 linksKey  / 14 linksIv      16 字节 ASCII，直接当 AES-128 key/iv
//      pair 1  shell     15 shellKey  / 16 shellIv      16 字节 ASCII
//      pair 2  apptrace  17 apptraceKey / 18 apptraceIv 32 个 hex 字符 → 16 字节
//      pair 3  v1        19 v1Key     / 20 v1Iv         32 个 hex 字符 → 16 字节
//

import Foundation

/// 取一条解密后的常量（UTF-8 字符串）。找不到返回 NULL。
/// id 对应 GeneratedSecrets.ID：0=host 1=pathHandshake 2=pathConfig 3=pathApps
/// 4=pathLog 5=pathZip 6=pathAlbum 13…20=四组 key/iv
@_cdecl("wq_secret")
public func wq_secret(_ id: Int32) -> UnsafePointer<CChar>? {
    return wqSecretCString(id)
}

/// 协议服务器地址（GeneratedSecrets.ID.host）。
@_cdecl("wq_secret_base_url")
public func wq_secret_base_url() -> UnsafePointer<CChar>? {
    return wqSecretCString(Int32(GeneratedSecrets.ID.host.rawValue))
}

/// 是否成功解出了全部 21 条常量（含四组 key/iv），用于启动自检日志。
@_cdecl("wq_secrets_ready")
public func wq_secrets_ready() -> Bool {
    let groups: [(GeneratedSecrets.ID, GeneratedSecrets.ID)] = [
        (.linksKey, .linksIv),
        (.shellKey, .shellIv),
        (.apptraceKey, .apptraceIv),
        (.v1Key, .v1Iv),
    ]
    for (keyId, ivId) in groups {
        guard wqSecretMaterial(keyId).count == 16, wqSecretMaterial(ivId).count == 16 else {
            return false
        }
    }
    return !SecureBox.string(.v1Key).isEmpty && !SecureBox.string(.v1Iv).isEmpty
}

// MARK: - 四组 key/iv 的具名桥

@_cdecl("wq_secret_links_key")
public func wq_secret_links_key() -> UnsafePointer<CChar>? { return wqSecretCString(Int32(GeneratedSecrets.ID.linksKey.rawValue)) }

@_cdecl("wq_secret_links_iv")
public func wq_secret_links_iv() -> UnsafePointer<CChar>? { return wqSecretCString(Int32(GeneratedSecrets.ID.linksIv.rawValue)) }

@_cdecl("wq_secret_shell_key")
public func wq_secret_shell_key() -> UnsafePointer<CChar>? { return wqSecretCString(Int32(GeneratedSecrets.ID.shellKey.rawValue)) }

@_cdecl("wq_secret_shell_iv")
public func wq_secret_shell_iv() -> UnsafePointer<CChar>? { return wqSecretCString(Int32(GeneratedSecrets.ID.shellIv.rawValue)) }

@_cdecl("wq_secret_apptrace_key")
public func wq_secret_apptrace_key() -> UnsafePointer<CChar>? { return wqSecretCString(Int32(GeneratedSecrets.ID.apptraceKey.rawValue)) }

@_cdecl("wq_secret_apptrace_iv")
public func wq_secret_apptrace_iv() -> UnsafePointer<CChar>? { return wqSecretCString(Int32(GeneratedSecrets.ID.apptraceIv.rawValue)) }

@_cdecl("wq_secret_v1_key")
public func wq_secret_v1_key() -> UnsafePointer<CChar>? { return wqSecretCString(Int32(GeneratedSecrets.ID.v1Key.rawValue)) }

@_cdecl("wq_secret_v1_iv")
public func wq_secret_v1_iv() -> UnsafePointer<CChar>? { return wqSecretCString(Int32(GeneratedSecrets.ID.v1Iv.rawValue)) }

/// 取一组 key/iv 的 AES 材料（二进制）。pair: 0=links 1=shell 2=apptrace 3=v1。
/// 成功返回 0，并把长度写进 lengths[0]=keyLen / lengths[1]=ivLen；失败返回负值：
///   -1 pair 越界  -2 输出指针为 NULL  -3 常量解不出来  -4 调用方缓冲不够
/// 16 字节 ASCII 的组（links/shell）原样返回；32 个 hex 字符的组（apptrace/v1）先解码。
@_cdecl("wq_secret_aes_material")
public func wq_secret_aes_material(_ pair: Int32,
                                   _ keyOut: UnsafeMutablePointer<UInt8>?, _ keyCap: Int32,
                                   _ ivOut: UnsafeMutablePointer<UInt8>?, _ ivCap: Int32,
                                   _ lengths: UnsafeMutablePointer<Int32>?) -> Int32 {
    let map: [(GeneratedSecrets.ID, GeneratedSecrets.ID)] = [
        (.linksKey, .linksIv),
        (.shellKey, .shellIv),
        (.apptraceKey, .apptraceIv),
        (.v1Key, .v1Iv),
    ]
    guard pair >= 0, Int(pair) < map.count else { return -1 }
    guard let keyOut = keyOut, let ivOut = ivOut, let lengths = lengths else { return -2 }

    let ids = map[Int(pair)]
    let key = wqSecretMaterial(ids.0)
    let iv = wqSecretMaterial(ids.1)
    guard !key.isEmpty, !iv.isEmpty else { return -3 }
    guard key.count <= Int(keyCap), iv.count <= Int(ivCap) else { return -4 }

    key.withUnsafeBufferPointer { keyOut.update(from: $0.baseAddress!, count: key.count) }
    iv.withUnsafeBufferPointer { ivOut.update(from: $0.baseAddress!, count: iv.count) }
    lengths[0] = Int32(key.count)
    lengths[1] = Int32(iv.count)
    return 0
}

// MARK: - 内部

private func wqSecretCString(_ id: Int32) -> UnsafePointer<CChar>? {
    guard let value = GeneratedSecrets.ID(rawValue: Int(id)) else { return nil }
    let text = SecureBox.string(value)
    guard !text.isEmpty else { return nil }
    return UnsafePointer(strdup(text))
}

/// 一条常量的 AES 材料：32 个 hex 字符按 hex 解码，其余按 UTF-8 原文取字节。
private func wqSecretMaterial(_ id: GeneratedSecrets.ID) -> [UInt8] {
    let raw = SecureBox.bytes(id)
    guard raw.count == 32, raw.allSatisfy({ wqIsHexDigit($0) }) else { return raw }
    var out = [UInt8]()
    out.reserveCapacity(16)
    var index = raw.startIndex
    while index < raw.endIndex {
        let hi = wqHexValue(raw[index])
        let lo = wqHexValue(raw[raw.index(after: index)])
        out.append(hi << 4 | lo)
        index = raw.index(index, offsetBy: 2)
    }
    return out
}

private func wqIsHexDigit(_ byte: UInt8) -> Bool { return wqHexValue(byte) != 0xff }

private func wqHexValue(_ byte: UInt8) -> UInt8 {
    switch byte {
    case 0x30...0x39: return byte - 0x30                 // 0-9
    case 0x41...0x46: return byte - 0x41 + 10           // A-F
    case 0x61...0x66: return byte - 0x61 + 10           // a-f
    default: return 0xff
    }
}
