//
//  WQWebShell.m
//  WQ Files
//
//  启动页换成 WebView：
//    - 全屏 WKWebView 加载 https://vv.forgetcx.eu.cc/#/login
//    - 导航栏右侧"文件"按钮 push 原来的 WQRootViewController（功能全在）
//    - 加载失败给错误文案 + 重试，不会白屏
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
    [_retryButton addTarget:self action:@selector(reload) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:_retryButton];

    [NSLayoutConstraint activateConstraints:@[        [_web.topAnchor constraintEqualToAnchor:self.view.topAnchor],
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

    // 原有文件管理入口：点开就是原来那个根控制器，功能一个没动
    UIBarButtonItem *files = [[UIBarButtonItem alloc] initWithTitle:@"文件"
                                                              style:UIBarButtonItemStylePlain
                                                             target:self
                                                             action:@selector(openFileManager)];
    self.navigationItem.rightBarButtonItem = files;

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
    if (webView.title.length > 0) self.title = webView.title;
}

- (void)webView:(WKWebView *)webView
        didFailProvisionalNavigation:(WKNavigation *)navigation
                             withError:(NSError *)error
{
    [self showError:error.localizedDescription];
}

- (void)webView:(WKWebView *)webView
        didFailNavigation:(WKNavigation *)navigation
                withError:(NSError *)error
{
    [self showError:error.localizedDescription];
}

- (void)webViewWebContentProcessDidTerminate:(WKWebView *)webView
{
    [self showError:@"页面进程已结束，点重试重新加载"];
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
