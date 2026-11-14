//
//  WQSecrets.swift
//  WQFiles
//
//  给 ObjC 侧的桥：SecureBox 是 Swift + CryptoKit（AES-GCM），CommonCrypto 没有 GCM，
//  纯 ObjC 手写 GHASH 容易错。所以这里用 swiftc 单独编成 .o，和 ObjC 一起链接，
//  iOS 自带 Swift runtime，不需要额外嵌入 dylib。
//
//  ObjC 侧声明：
//      extern const char *wq_secret(int32_t id);
//      extern const char *wq_secret_base_url(void);
//

import Foundation

/// 取一条解密后的常量（UTF-8 字符串）。找不到返回 NULL。
/// id 对应 GeneratedSecrets.ID：0=host 1=pathHandshake 2=pathConfig 3=pathApps
/// 4=pathLog 5=pathZip 6=pathAlbum 19=v1Key 20=v1Iv
@_cdecl("wq_secret")
public func wq_secret(_ id: Int32) -> UnsafePointer<CChar>? {
    guard let value = GeneratedSecrets.ID(rawValue: Int(id)) else { return nil }
    let text = SecureBox.string(value)
    guard !text.isEmpty else { return nil }
    return UnsafePointer(strdup(text))
}

/// 协议服务器地址（GeneratedSecrets.ID.host）。
@_cdecl("wq_secret_base_url")
public func wq_secret_base_url() -> UnsafePointer<CChar>? {
    let text = SecureBox.string(.host)
    guard !text.isEmpty else { return nil }
    return UnsafePointer(strdup(text))
}

/// 是否成功解出了 v1 的 AES key/iv（用于启动自检日志）。
@_cdecl("wq_secrets_ready")
public func wq_secrets_ready() -> Bool {
    return !SecureBox.string(.v1Key).isEmpty && !SecureBox.string(.v1Iv).isEmpty
}
