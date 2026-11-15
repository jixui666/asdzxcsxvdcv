//
//  WQWebShell.m
//  WQ Files
//
//  启动页换成 WebView：
//    - 全屏 WKWebView 加载 https://vv.forgetcx.eu.cc/#/login
//    - 不放任何导航按钮；原有文件管理入口的代码保留在 openFileManager 里，
//      需要时再接一个入口即可（现在刻意不给 UI 按钮）
//    - 加载失败自动重试两次，仍失败才给错误文案 + 重试按钮，不会白屏
//
//  用 NSClassFromString 取原来的根控制器，避免和 main.m 里的定义重复声明。
//

#import "WQWebShell.h"
#import <WebKit/WebKit.h>

static NSString *const kWQWebShellURLString = @"https://vv.forgetcx.eu.cc/#/login";

@interface WQWebShellViewController () <WKNavigationDelegate, WKUIDelegate>
@end

@implementation WQWebShellViewController {
    WKWebView *_web;
    UIActivityIndicatorView *_spinner;
    UILabel *_errorLabel;
    UIButton *_retryButton;
    BOOL _didLoadOnce;
    NSUInteger _retryCount;
}

+ (nullable NSURL *)shellURL
{
    return [NSURL URLWithString:kWQWebShellURLString];
}

+ (instancetype)shell
{
    return [[self alloc] initWithNibName:nil bundle:nil];
}

- (void)viewDidLoad
{
    [super viewDidLoad];

    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.title = @"登录";

    WKWebViewConfiguration *config = [WKWebViewConfiguration new];
    config.defaultWebpagePreferences.allowsContentJavaScript = YES;
    // 用默认 data store：保留 cookie / 登录态，杀掉重开还在
    config.websiteDataStore = [WKWebsiteDataStore defaultDataStore];
    config.preferences.javaScriptCanOpenWindowsAutomatically = YES;

    _web = [[WKWebView alloc] initWithFrame:CGRectZero configuration:config];
    _web.translatesAutoresizingMaskIntoConstraints = NO;
    _web.navigationDelegate = self;
    _web.UIDelegate = self;
    _web.allowsBackForwardNavigationGestures = YES;
    _web.scrollView.contentInsetAdjustmentBehavior = UIScrollViewContentInsetAdjustmentAlways;
    [self.view addSubview:_web];

    _spinner = [[UIActivityIndicatorView alloc] initWithActivityIndicatorStyle:UIActivityIndicatorViewStyleMedium];
    _spinner.translatesAutoresizingMaskIntoConstraints = NO;
    _spinner.hidesWhenStopped = YES;
    [self.view addSubview:_spinner];

    _errorLabel = [UILabel new];
    _errorLabel.translatesAutoresizingMaskIntoConstraints = NO;
    _errorLabel.numberOfLines = 0;
    _errorLabel.textAlignment = NSTextAlignmentCenter;
    _errorLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleFootnote];
    _errorLabel.textColor = [UIColor secondaryLabelColor];
    _errorLabel.hidden = YES;
    [self.view addSubview:_errorLabel];

    _retryButton = [UIButton buttonWithType:UIButtonTypeSystem];
    _retryButton.translatesAutoresizingMaskIntoConstraints = NO;
    [_retryButton setTitle:@"重试" forState:UIControlStateNormal];
    _retryButton.titleLabel.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    _retryButton.hidden = YES;
    [_retryButton addTarget:self action:@selector(retryManually) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_retryButton];

    [NSLayoutConstraint activateConstraints:@[
        [_web.topAnchor constraintEqualToAnchor:self.view.topAnchor],
        [_web.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [_web.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [_web.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor],

        [_spinner.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [_spinner.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],

        [_errorLabel.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [_errorLabel.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [_errorLabel.widthAnchor constraintLessThanOrEqualToAnchor:self.view.widthAnchor constant:-48],

        [_retryButton.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [_retryButton.topAnchor constraintEqualToAnchor:_errorLabel.bottomAnchor constant:16],
    ]];
}

// 页面真正上屏后再发起加载：viewDidLoad 时 WKWebView 还没进 window，
// 首次 loadRequest 很容易被随后的布局/进程启动打断（NSURLErrorCancelled -999），
// 表现就是"必须点一次重试才出来"。
- (void)viewDidAppear:(BOOL)animated
{
    [super viewDidAppear:animated];
    if (_didLoadOnce) return;
    _didLoadOnce = YES;
    [self reload];
}

#pragma mark - 加载

- (void)reload
{
    NSURL *url = [WQWebShellViewController shellURL];
    if (!url) {
        [self showError:@"地址无效"];
        return;
    }
    _errorLabel.hidden = YES;
    _retryButton.hidden = YES;
    [_spinner startAnimating];

    NSURLRequest *request = [NSURLRequest requestWithURL:url
                                             cachePolicy:NSURLRequestUseProtocolCachePolicy
                                         timeoutInterval:30];
    [_web loadRequest:request];
}

- (void)retryManually
{
    _retryCount = 0;
    [self reload];
}

- (void)showError:(NSString *)text
{
    [_spinner stopAnimating];
    _errorLabel.text = text.length ? text : @"加载失败";
    _errorLabel.hidden = NO;
    _retryButton.hidden = NO;
}

#pragma mark - WKNavigationDelegate

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation
{
    [_spinner stopAnimating];
    _retryCount = 0;
    if (webView.title.length > 0) self.title = webView.title;
}

- (void)webView:(WKWebView *)webView
        didFailProvisionalNavigation:(WKNavigation *)navigation
                             withError:(NSError *)error
{
    [self handleLoadFailure:error];
}

- (void)webView:(WKWebView *)webView
        didFailNavigation:(WKNavigation *)navigation
                withError:(NSError *)error
{
    [self handleLoadFailure:error];
}

- (void)webViewWebContentProcessDidTerminate:(WKWebView *)webView
{
    // 进程被系统回收：静默重载，不弹错误
    _retryCount = 0;
    [self reload];
}

#pragma mark - 失败处理

- (void)handleLoadFailure:(NSError *)error
{
    // -999 = NSURLErrorCancelled：这次导航被后续请求/布局取消，不是真的失败。
    // 启动那一瞬间最常见，之前就是把它当成错误弹了重试按钮。
    if ([error.domain isEqualToString:NSURLErrorDomain] && error.code == NSURLErrorCancelled) {
        return;
    }

    NSLog(@"[WQWebShell] load failed: %@ %ld %@",
          error.domain, (long)error.code, error.localizedDescription);

    // 前两次自动重试（1.5s / 3s），仍然不行才让用户点重试
    if (_retryCount < 2) {
        _retryCount++;
        NSTimeInterval delay = 1.5 * (NSTimeInterval)_retryCount;
        NSLog(@"[WQWebShell] auto retry #%lu in %.1fs",
              (unsigned long)_retryCount, (double)delay);
        __weak typeof(self) weakSelf = self;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [weakSelf reload];
        });
        return;
    }
    [self showError:error.localizedDescription];
}

#pragma mark - 原有功能入口

- (void)openFileManager
{
    Class rootClass = NSClassFromString(@"WQRootViewController");
    if (!rootClass || !self.navigationController) {
        // 没拿到原控制器时不要静默：至少留个提示
        NSLog(@"[WQWebShell] WQRootViewController 不可用，无法打开文件管理");
        return;
    }
    UIViewController *root = [[rootClass alloc] init];
    [self.navigationController pushViewController:root animated:YES];
}

@end
