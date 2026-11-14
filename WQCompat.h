//
//  WQCompat.h
//  WQ Files
//
//  CI 的 Xcode（macos-15，iOS 18 SDK）比 WQFiles 的目标 SDK 旧，
//  缺少 iOS 26 才有的枚举。这里按 SDK 版本补齐，数值与 iOS 26 保持一致。
//  build.sh 用 -include 强制包含，所以不需要在每个 .m 里手动 import。
//

#ifndef WQCompat_h
#define WQCompat_h

#import <UIKit/UIKit.h>

// 编译期常量（host / api/k7m3q9x2/* / 四组 key/iv）的 C 桥声明。强制包含，
// 让任何 .m 都能直接调 wq_secret() / wq_secret_aes_material()。
#import "WQSecretsBridge.h"

#if __IPHONE_OS_VERSION_MAX_ALLOWED < 260000
// UIBarButtonItemStyleProminent 在 iOS 26 里是 NS_ENUM 值 3。
#define UIBarButtonItemStyleProminent ((UIBarButtonItemStyle)3)
#endif

#endif /* WQCompat_h */
