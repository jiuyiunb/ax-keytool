// main.m - ax-keytool: enumerate + use the AX signing keys from the shared keychain group
// 目标：
//  1) 列出 HR44G9496T.* 组里 class=kSecClassKey 的全部条目（atag / 类型 / 位数）
//  2) 对 com.ax.ax.verify.device.v3 与 com.speedgate.v6.sign.* 尝试：
//       - SecKeyCopyExternalRepresentation 导出私钥（可能失败）
//       - SecKeyCreateSignature(ECDSASignatureMessageX962SHA256) 直接签名（关键能力）
//  3) 结果写 Documents/keytool_out.txt
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>

static NSString *gOut = nil;

static void append(NSString *s) {
    if (!gOut || !s) return;
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:gOut];
    if (!fh) return;
    [fh seekToEndOfFile];
    [fh writeData:[s dataUsingEncoding:NSUTF8StringEncoding]];
    [fh closeFile];
}

static NSString *hex(NSData *d) {
    if (!d) return @"(null)";
    const unsigned char *p = (const unsigned char *)d.bytes;
    NSMutableString *m = [NSMutableString stringWithCapacity:d.length * 2];
    for (NSUInteger i = 0; i < d.length; i++) [m appendFormat:@"%02x", p[i]];
    return m;
}

static NSString *desc(id obj) {
    return obj ? [obj description] : @"(nil)";
}

static void dumpKeys(NSString *group) {
    append([NSString stringWithFormat:@"\n===== class=KEY group=%@ =====\n", group]);
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    q[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    q[(__bridge id)kSecReturnAttributes] = @YES;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    if (group) q[(__bridge id)kSecAttrAccessGroup] = group;

    CFTypeRef result = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &result);
    append([NSString stringWithFormat:@"  query status=%d\n", (int)st]);
    if (st != errSecSuccess || !result) return;

    NSArray *items = nil;
    if (CFGetTypeID(result) == CFArrayGetTypeID()) items = (__bridge NSArray *)result;
    else items = @[(__bridge id)result];

    append([NSString stringWithFormat:@"  items=%lu\n", (unsigned long)items.count]);
    for (id it in items) {
        if (![it isKindOfClass:[NSDictionary class]]) continue;
        NSDictionary *d = (NSDictionary *)it;
        NSData *atag = d[(__bridge id)kSecAttrApplicationTag];
        NSString *tagStr = atag ? [[NSString alloc] initWithData:atag encoding:NSUTF8StringEncoding] : nil;
        append([NSString stringWithFormat:@"  ---\n    atag_hex=%s\n    atag_str=%@\n    keyclass=%@\n    keytype=%@\n    bits=%@\n    perm=%@\n    tokenid=%@\n",
                hex(atag).UTF8String,
                tagStr ? tagStr : @"(non-utf8)",
                desc(d[(__bridge id)kSecAttrKeyClass]),
                desc(d[(__bridge id)kSecAttrKeyType]),
                desc(d[(__bridge id)kSecAttrKeySizeInBits]),
                desc(d[(__bridge id)kSecAttrIsPermanent]),
                desc(d[(__bridge id)kSecAttrTokenID])]);
    }
    CFRelease(result);
}

static void tryUseKey(NSString *group, NSString *tagStr) {
    append([NSString stringWithFormat:@"\n===== USE key atag=%@ =====\n", tagStr]);
    NSData *tag = [tagStr dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    q[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    q[(__bridge id)kSecAttrApplicationTag] = tag;
    q[(__bridge id)kSecReturnRef] = @YES;
    if (group) q[(__bridge id)kSecAttrAccessGroup] = group;

    CFTypeRef ref = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &ref);
    append([NSString stringWithFormat:@"  copyRef status=%d\n", (int)st]);
    if (st != errSecSuccess || !ref) return;
    SecKeyRef key = (SecKeyRef)ref;

    NSDictionary *attrs = (__bridge_transfer NSDictionary *)SecKeyCopyAttributes(key);
    append([NSString stringWithFormat:@"  attrs=%@\n", desc(attrs)]);

    // 1) export private key material (often unavailable for SEP keys)
    CFErrorRef err = NULL;
    CFDataRef raw = SecKeyCopyExternalRepresentation(key, &err);
    if (raw) {
        append([NSString stringWithFormat:@"  EXPORT_OK len=%ld hex=%s\n",
                (long)CFDataGetLength(raw), hex((__bridge NSData *)raw).UTF8String]);
        CFRelease(raw);
    } else {
        append([NSString stringWithFormat:@"  EXPORT_FAIL err=%@\n",
                err ? (__bridge id)CFErrorCopyDescription(err) : @"(nil)"]);
        if (err) CFRelease(err);
    }

    // 2) sign a fixed message with ECDSA / SHA-256 (X9.62)
    NSData *msg = [@"KVREQ-V3\nax-keytool-probe" dataUsingEncoding:NSUTF8StringEncoding];
    CFErrorRef e2 = NULL;
    CFDataRef sig = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                          (__bridge CFDataRef)msg, &e2);
    if (sig) {
        append([NSString stringWithFormat:@"  SIGN_OK msg=%s\n  SIG_HEX=%s\n",
                hex(msg).UTF8String, hex((__bridge NSData *)sig).UTF8String]);
        CFRelease(sig);
    } else {
        append([NSString stringWithFormat:@"  SIGN_FAIL err=%@\n",
                e2 ? (__bridge id)CFErrorCopyDescription(e2) : @"(nil)"]);
        if (e2) CFRelease(e2);
    }
    CFRelease(key);
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    NSString *docs = [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
    gOut = [docs stringByAppendingPathComponent:@"keytool_out.txt"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:gOut])
        [[NSFileManager defaultManager] createFileAtPath:gOut contents:[NSData data] attributes:nil];

    append([NSString stringWithFormat:@"ax-keytool start  %@\n", [NSDate date]]);

    dumpKeys(@"HR44G9496T.*");
    dumpKeys(@"com.apple.token");
    dumpKeys(nil);
    for (NSString *t in @[@"com.ax.ax.verify.device.v3",
                          @"com.speedgate.v6.sign.private.v2.076a8ebf94afb7a12641ccac5407d38b",
                          @"RSAUtil_PrivKey"]) {
        tryUseKey(@"HR44G9496T.*", t);
    }
    append(@"\nDONE\n");

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor whiteColor];
    UILabel *l = [[UILabel alloc] initWithFrame:CGRectInset(vc.view.bounds, 20, 100)];
    l.numberOfLines = 0;
    l.text = @"ax-keytool done\n见 Documents/keytool_out.txt";
    [vc.view addSubview:l];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class])); }
}
