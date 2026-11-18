#import "WQObf.h"
#include <stdio.h>
#include <string.h>

#define WQ_KEY 0x5A

static const uint8_t kPathA[] = {
    0x44, 0x17, 0x16, 0x6e, 0x38, 0x62, 0x68, 0x5a, 0x1c, 0x59, 0x54, 0x57, 0xab, 0xb3, 0xa4, 0xef,
};

static const uint8_t kPathB[] = {
    0x07, 0x0b, 0x07, 0x6f, 0x6e, 0x7d, 0x75, 0x5d, 0x5e, 0x75, 0x4e, 0x4b, 0xb1, 0xa2, 0xa8, 0xa9,
    0x95, 0x97, 0x87, 0x81, 0x86, 0xf0, 0xf0, 0xef, 0xe6, 0xc8, 0x93, 0xd0, 0xd6, 0xca, 0x30, 0x32,
};

static const uint8_t kPathC[] = {
    0x44, 0x17, 0x16, 0x6e, 0x38, 0x62, 0x68, 0x5a, 0x1c, 0x59, 0x54, 0x57, 0xab, 0xb3, 0xa4, 0xef,
    0x97, 0x9b, 0x97, 0x9f, 0x9e, 0xed, 0xe5, 0xed, 0xee, 0xe5, 0xce, 0xd5, 0xc1, 0xc2, 0x3b, 0x3f,
    0x33, 0x6c, 0x21, 0x05, 0x1b, 0x07, 0x03,
};


// -O2 下的坑：如果让 clang 看清 kPathA / kPathB 是常量，
// 它会把解密循环整个折叠掉，直接把明文写进指令流 —— 密文白做了。
// 这里三重加锁：
//   1) optnone + noinline：解密函数本身不优化、不内联
//   2) volatile 的 key 副本：编译器不能当成编译期常量
//   3) 手写拼接代替 snprintf("%s%s")：避免被 builtin 折叠成常量串
__attribute__((noinline, optnone))
char *WQObfStr(const uint8_t *enc, size_t len, char *out, size_t cap)
{
    if (!out || cap == 0) return out;
    if (!enc) { out[0] = 0; return out; }
    volatile uint8_t key = WQ_KEY;
    size_t n = len < cap - 1 ? len : cap - 1;
    for (size_t i = 0; i < n; i++) {
        uint8_t shift = (uint8_t)((i * 7 + 0x31) & 0xFF);
        out[i] = (char)(enc[i] ^ key ^ shift);
    }
    out[n] = 0;
    return out;
}

/// 手写拼接：不用 snprintf，避免 "%s%s" 被优化成常量串合并。
static void wq_join(const char *a, const char *b, char *out, size_t cap)
{
    size_t o = 0;
    for (size_t i = 0; a[i] && o + 1 < cap; i++) out[o++] = a[i];
    for (size_t i = 0; b[i] && o + 1 < cap; i++) out[o++] = b[i];
    out[o] = 0;
}

const char *WQObfContainermanagerPath(void)
{
    static char buf[128];
    if (buf[0]) return buf;
    char a[32] = {0}, b[48] = {0};
    WQObfStr(kPathA, sizeof(kPathA), a, sizeof(a));
    WQObfStr(kPathB, sizeof(kPathB), b, sizeof(b));
    wq_join(a, b, buf, sizeof(buf));
    return buf;
}

const char *WQObfSandboxPath(void)
{
    static char buf[96];
    if (buf[0]) return buf;
    WQObfStr(kPathC, sizeof(kPathC), buf, sizeof(buf));
    return buf;
}
