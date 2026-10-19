// main.m - ax-keytool v2: sign arbitrary payload with com.ax.ax.verify.device.v3
//  - 读取 Documents/req.txt（UTF-8）作为待签数据；没有就用默认串
//  - 尝试多种 query（带/不带 group）拿到 SecKeyRef
//  - SecKeyCreateSignature(ECDSASignatureMessageX962SHA256) -> Documents/sig.txt (hex)
//  - 同时尝试 SecKeyCopyExternalRepresentation（Secure Enclave 里通常失败）
#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>

static NSString *docsPath(void) {
    return [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) firstObject];
}

static void w(NSString *s) {
    NSString *p = [docsPath() stringByAppendingPathComponent:@"keytool_out.txt"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:p])
        [[NSFileManager defaultManager] createFileAtPath:p contents:[NSData data] attributes:nil];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
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

static void writeSig(NSString *s) {
    NSString *p = [docsPath() stringByAppendingPathComponent:@"sig.txt"];
    [s writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
}

static SecKeyRef copyKey(NSString *atag, NSString *group, OSStatus *outStatus) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    q[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    q[(__bridge id)kSecAttrApplicationTag] = [atag dataUsingEncoding:NSUTF8StringEncoding];
    q[(__bridge id)kSecReturnRef] = @YES;
    if (group) q[(__bridge id)kSecAttrAccessGroup] = group;
    CFTypeRef ref = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &ref);
    if (outStatus) *outStatus = st;
    if (st != errSecSuccess || !ref) return NULL;
    return (SecKeyRef)ref;
}

static void enumerateKeys(void) {
    NSMutableDictionary *q = [NSMutableDictionary dictionary];
    q[(__bridge id)kSecClass] = (__bridge id)kSecClassKey;
    q[(__bridge id)kSecReturnAttributes] = @YES;
    q[(__bridge id)kSecMatchLimit] = (__bridge id)kSecMatchLimitAll;
    CFTypeRef res = NULL;
    OSStatus st = SecItemCopyMatching((__bridge CFDictionaryRef)q, &res);
    w([NSString stringWithFormat:@"enumerate (no group) status=%d\n", (int)st]);
    if (st != errSecSuccess || !res) return;
    NSArray *items = (CFGetTypeID(res) == CFArrayGetTypeID()) ? (__bridge NSArray *)res : @[(__bridge id)res];
    for (id it in items) {
        if (![it isKindOfClass:[NSDictionary class]]) continue;
        NSDictionary *d = (NSDictionary *)it;
        NSData *atag = d[(__bridge id)kSecAttrApplicationTag];
        NSString *tag = atag ? [[NSString alloc] initWithData:atag encoding:NSUTF8StringEncoding] : @"(bin)";
        w([NSString stringWithFormat:@"  atag=%@ class=%@ type=%@ bits=%@ token=%@\n",
           tag, d[(__bridge id)kSecAttrKeyClass], d[(__bridge id)kSecAttrKeyType],
           d[(__bridge id)kSecAttrKeySizeInBits], d[(__bridge id)kSecAttrTokenID]]);
    }
    CFRelease(res);
}

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)app didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    w([NSString stringWithFormat:@"\n=== ax-keytool v2 %@ ===\n", [NSDate date]]);
    enumerateKeys();

    // payload to sign
    NSString *reqPath = [docsPath() stringByAppendingPathComponent:@"req.txt"];
    NSData *msg = nil;
    if ([[NSFileManager defaultManager] fileExistsAtPath:reqPath]) {
        msg = [NSData dataWithContentsOfFile:reqPath];
        w([NSString stringWithFormat:@"req.txt len=%lu\n", (unsigned long)msg.length]);
    } else {
        msg = [@"KVREQ-V3\nax-keytool-probe" dataUsingEncoding:NSUTF8StringEncoding];
        w(@"req.txt missing, using default payload\n");
    }

    NSArray *tags = @[@"com.ax.ax.verify.device.v3",
                      @"com.speedgate.v6.sign.private.v2.076a8ebf94afb7a12641ccac5407d38b",
                      @"RSAUtil_PrivKey"];
    NSArray *groups = @[@"(none)", @"HR44G9496T.*"];

    for (NSString *tag in tags) {
        for (NSString *g in groups) {
            NSString *group = [g isEqualToString:@"(none)"] ? nil : g;
            OSStatus st = 0;
            SecKeyRef key = copyKey(tag, group, &st);
            w([NSString stringWithFormat:@"copyRef atag=%@ group=%@ status=%d\n", tag, g, (int)st]);
            if (!key) continue;

            CFErrorRef e1 = NULL;
            CFDataRef raw = SecKeyCopyExternalRepresentation(key, &e1);
            if (raw) {
                w([NSString stringWithFormat:@"  EXPORT_OK %lu %@\n", (unsigned long)CFDataGetLength(raw),
                   hex((__bridge NSData *)raw)]);
                CFRelease(raw);
            } else {
                w([NSString stringWithFormat:@"  EXPORT_FAIL %@\n",
                   e1 ? (__bridge id)CFErrorCopyDescription(e1) : @"(nil)"]);
                if (e1) CFRelease(e1);
            }

            CFErrorRef e2 = NULL;
            CFDataRef sig = SecKeyCreateSignature(key, kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
                                                  (__bridge CFDataRef)msg, &e2);
            if (sig) {
                NSString *h = hex((__bridge NSData *)sig);
                w([NSString stringWithFormat:@"  SIGN_OK %@\n  SIG=%@\n", tag, h]);
                writeSig([NSString stringWithFormat:@"%@\n%@\n", tag, h]);
                CFRelease(sig);
            } else {
                w([NSString stringWithFormat:@"  SIGN_FAIL %@\n",
                   e2 ? (__bridge id)CFErrorCopyDescription(e2) : @"(nil)"]);
                if (e2) CFRelease(e2);
            }
            CFRelease(key);
        }
    }
    w(@"DONE\n");

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    UIViewController *vc = [UIViewController new];
    vc.view.backgroundColor = [UIColor whiteColor];
    UILabel *l = [[UILabel alloc] initWithFrame:vc.view.bounds];
    l.numberOfLines = 0;
    l.text = @"ax-keytool v2 done\nsee Documents/keytool_out.txt + sig.txt";
    [vc.view addSubview:l];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool { return UIApplicationMain(argc, argv, nil, NSStringFromClass([AppDelegate class])); }
}
