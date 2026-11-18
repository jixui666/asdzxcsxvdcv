#ifndef WQObf_h
#define WQObf_h

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// 把密文就地解成 C 字符串（写入 out，最多 cap-1 字节 + NUL）。
/// 加密方式：byte ^ 0x5A ^ ((i*7+0x31) & 0xFF)。
char *WQObfStr(const uint8_t *enc, size_t len, char *out, size_t cap);

/// containermanagerd 的 dylib 路径（运行时拼出来，二进制里没有明文）。
const char *WQObfContainermanagerPath(void);

/// sandbox dylib 路径。
const char *WQObfSandboxPath(void);

#ifdef __cplusplus
}
#endif

#endif /* WQObf_h */
