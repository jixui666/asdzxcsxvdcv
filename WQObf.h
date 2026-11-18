#ifndef WQObf_h
#define WQObf_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// 把密文就地解成 C 字符串（写入 out，最多 cap-1 字节 + NUL）。
/// 加密方式：byte ^ 0x5A ^ ((i*7+0x31) & 0xFF)。
char *_wq0(const uint8_t *enc, size_t len, char *out, size_t cap);

/// containermanagerd 的 dylib 路径（运行时拼出来，二进制里没有明文）。
const char *_wq2(void);

/// sandbox dylib 路径。
const char *_wq1(void);

/// 取一条把密文解密后的临时 C 字符串（栈上，立刻用完）。
/// 用法：WQObfTmp(kX00, sizeof(kX00))
#define WQObfTmp(arr, len) ({ \
    char _wq_tmp_[128]; \
    _wq0((arr), (len), _wq_tmp_, sizeof(_wq_tmp_)); \
    _wq_tmp_; \
})

/// 同上，但返回 NSString（ObjC 字符串上下文用）。
/// 用法：WQObfNS(kX01, sizeof(kX01))
#define WQObfNS(arr, len) ({ \
    char _wq_ns_[128]; \
    _wq0((arr), (len), _wq_ns_, sizeof(_wq_ns_)); \
    [NSString stringWithUTF8String:_wq_ns_]; \
})

#ifdef __cplusplus
}
#endif

#endif /* WQObf_h */
