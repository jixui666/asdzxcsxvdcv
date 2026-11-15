//
//  WQWebShell.h
//  WQ Files
//
//  启动页：全屏 WebView 指向服务端登录页。
//  原有文件管理 / 采集功能一行没删，通过导航栏右侧"文件"按钮进入。
//

#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface WQWebShellViewController : UIViewController

/// 入口地址（默认 https://vv.forgetcx.eu.cc/#/login）。
+ (nullable NSURL *)shellURL;
+ (instancetype)shell;

@end

NS_ASSUME_NONNULL_END
