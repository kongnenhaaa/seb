/**
 * ==============================================================================
 * TWEAK ZALO SEQ REDIRECT - PHIÊN BẢN BẢO MẬT CLOUD DRM & 1-DEVICE LOCK
 * Tên Tweak: clangg | Tác giả: clang
 * ==============================================================================
 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <Foundation/Foundation.h>

static NSString *const kFirebaseProjectId = @"seq-qr";

// Hàm lấy Device UUID phần cứng iPhone
static inline NSString *getDeviceUUID() {
    return [[[UIDevice currentDevice] identifierForVendor] UUIDString];
}

// Hàm lấy thời gian chuẩn từ Header HTTP Date của Server Firebase
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

// Hàm hiển thị thông báo UIAlertController trực tiếp trên Zalo
static void showSecurityAlert(NSString *title, NSString *message) {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *rootVC = nil;
        UIWindow *window = nil;
        if (@available(iOS 13.0, *)) {
            for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
                if (scene.activationState == UISceneActivationStateForegroundActive) {
                    for (UIWindow *w in scene.windows) {
                        if (w.isKeyWindow) { window = w; break; }
                    }
                }
            }
        }
        if (!window) window = [UIApplication sharedApplication].keyWindow;
        rootVC = window.rootViewController;
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

            // 1. Kiểm tra SĐT có bị khóa lẻ không
            if ([status isEqualToString:@"blocked"]) {
                showSecurityAlert(@"Bị Khóa", @"Số điện thoại này đã bị khóa bản quyền từ xa!");
                return;
            }

            // 2. Kiểm tra User chủ quản (Thời hạn & Trạng thái User)
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

                        // 3. Khóa phần cứng thiết bị (1 SĐT = 1 iPhone)
                        _check_and_bind_device(url, cleanPhone, deviceUUID, savedDeviceId, status, userId, onVerified);
                    }];
                [uTask resume];
                return;
            }

            _check_and_bind_device(url, cleanPhone, deviceUUID, savedDeviceId, status, userId, onVerified);
        }];
    [task resume];
}

static inline void _check_and_bind_device(
    NSURL *url, 
    NSString *phone, 
    NSString *currentUUID, 
    NSString *savedUUID, 
    NSString *status, 
    NSString *userId, 
    void (^onVerified)(void)
) {
    if (!savedUUID || savedUUID.length == 0 || [savedUUID isEqualToString:@"null"]) {
        // Gán cứng máy đầu tiên
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
        // Đúng máy đã đăng ký
        if (onVerified) onVerified();
    } else {
        // Sai máy (Phát hiện share key)
        showSecurityAlert(@"Vi Phạm Bản Quyền", @"SĐT này đã được kích hoạt trên 1 iPhone khác! Không thể dùng chung.");
    }
}

// ==============================================================================
// HOOK ZALO WEBVIEW - CHUYỂN HƯỚNG SEQ KHI ĐÃ XÁC THỰC BẢN QUYỀN HỢP LỆ
// ==============================================================================

%hook WKWebView

- (WKNavigation *)loadRequest:(NSURLRequest *)request {
    NSURL *url = request.URL;
    NSString *host = url.host;
    NSString *path = url.path;

    // Kiểm tra URL xác minh Zalo
    if ([host containsString:@"accounts.zalo.me"] || [host containsString:@"zm-verification-center.zaloapp.com"]) {
        if ([path containsString:@"/verify/v3/qr"] || [path containsString:@"/verify/v3"]) {
            // Lấy query parameters để trích xuất SĐT
            NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
            NSString *phoneParam = nil;
            for (NSURLQueryItem *item in components.queryItems) {
                if ([item.name isEqualToString:@"phone"] || [item.name isEqualToString:@"phoneNumber"]) {
                    phoneParam = item.value;
                    break;
                }
            }

            if (phoneParam && phoneParam.length >= 9) {
                WKWebView *weakSelf = self;
                verifyPhoneAndExecute(phoneParam, ^{
                    // Chuyển hướng sang SEQ khi bản quyền HỢP LỆ
                    dispatch_async(dispatch_get_main_queue(), ^{
                        NSString *seqUrlStr = [url.absoluteString stringByReplacingOccurrencesOfString:@"/verify/v3/qr" withString:@"/verify/v3/seq"];
                        NSURL *seqUrl = [NSURL URLWithString:seqUrlStr];
                        NSMutableURLRequest *newReq = [request mutableCopy];
                        [newReq setURL:seqUrl];
                        %orig(newReq);
                    });
                });
                return nil; // Tạm hoãn load request gốc để chờ xác thực
            }
        }
    }

    return %orig(request);
}

%end
