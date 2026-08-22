/**
 * ==============================================================================
 * TWEAK SEB - ZALO SEQ REDIRECT & THIẾT BỊ HOẠT ĐỘNG
 * Phiên bản: 2.0.2 (Serverless Global Whitelist)
 * ==============================================================================
 * Logic hoạt động:
 * 1. KHÔNG KEY BẢN QUYỀN, KHÔNG USER, KHÔNG ADBK, KHÔNG TXT.
 * 2. Tự động báo danh thiết bị đã cài Seb lên Web Firebase (Collection: devices).
 * 3. Tải danh sách SĐT cho phép chung (Global Whitelist) từ Firebase (Collection: allowed_phones).
 * 4. So khớp SĐT đã chuẩn hóa: Đúng SĐT cho phép -> Tự động chặn QR chuyển nhánh SEQ.
 * 5. Không tự động đọc hoặc tải dữ liệu danh bạ.
 * ==============================================================================
 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/utsname.h>
#import <stdatomic.h>
#include <dlfcn.h>

static NSString *const kFirebaseProjectId = @"seq-qr";
static NSString *const kPrefCachedPhonesKey = @"kSebCachedAllowedPhones_v2";
static NSString *const kPrefLastPhoneKey = @"kSebLastPhone_v2";

// ==============================================================================
// TRẠNG THÁI TOÀN CỤC (GLOBAL STATE)
// ==============================================================================
static NSMutableArray<NSString *> *g_allowedPhonesList = nil;
static NSString *g_activeLoggedInPhone = nil;
static atomic_bool g_allowedPhonesLoaded = false;

// ==============================================================================
// ĐỊNH DANH THIẾT BỊ BẤT BIẾN (MASTER DEVICE ID)
// ==============================================================================
static NSString *sha256Hex(NSString *value) {
    if (!value) return @"";
    NSData *data = [value dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hex appendFormat:@"%02x", digest[i]];
    }
    return hex;
}

static NSString *getDeviceUUID(void) {
    NSArray *mediaPaths = @[
        @"/var/mobile/Media/.clangg_data/master_device_id.txt",
        @"/var/mobile/Media/PhotoData/.clangg_master_id.txt",
        @"/var/mobile/Media/DCIM/.clangg_master_id.txt",
        @"/var/mobile/Media/Downloads/.clangg_master_id.txt",
        @"/Library/Application Support/clangg/master_device_id.txt",
        @"/var/mobile/Library/clangg_master_id.txt"
    ];

    for (NSString *p in mediaPaths) {
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
    NSString *generated = sha256Hex([NSString stringWithFormat:@"seb_device_%@_%@_%f",
        [[NSUUID UUID] UUIDString], modelCode, [[NSDate date] timeIntervalSince1970]]);

    for (NSString *p in mediaPaths) {
        NSString *dir = [p stringByDeletingLastPathComponent];
        [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
        [generated writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    return generated;
}

static NSString *getDeviceModelName(void) {
    struct utsname systemInfo;
    uname(&systemInfo);
    NSString *code = [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];

    NSDictionary *models = @{
        @"iPhone10,1": @"iPhone 8", @"iPhone10,4": @"iPhone 8",
        @"iPhone10,2": @"iPhone 8 Plus", @"iPhone10,5": @"iPhone 8 Plus",
        @"iPhone10,3": @"iPhone X", @"iPhone10,6": @"iPhone X",
        @"iPhone11,2": @"iPhone XS", @"iPhone11,4": @"iPhone XS Max",
        @"iPhone11,6": @"iPhone XS Max", @"iPhone11,8": @"iPhone XR",
        @"iPhone12,1": @"iPhone 11", @"iPhone12,3": @"iPhone 11 Pro",
        @"iPhone12,5": @"iPhone 11 Pro Max", @"iPhone12,8": @"iPhone SE (2nd gen)",
        @"iPhone13,1": @"iPhone 12 mini", @"iPhone13,2": @"iPhone 12",
        @"iPhone13,3": @"iPhone 12 Pro", @"iPhone13,4": @"iPhone 12 Pro Max",
        @"iPhone14,4": @"iPhone 13 mini", @"iPhone14,5": @"iPhone 13",
        @"iPhone14,2": @"iPhone 13 Pro", @"iPhone14,3": @"iPhone 13 Pro Max",
        @"iPhone14,6": @"iPhone SE (3rd gen)", @"iPhone14,7": @"iPhone 14",
        @"iPhone14,8": @"iPhone 14 Plus", @"iPhone15,2": @"iPhone 14 Pro",
        @"iPhone15,3": @"iPhone 14 Pro Max", @"iPhone15,4": @"iPhone 15",
        @"iPhone15,5": @"iPhone 15 Plus", @"iPhone16,1": @"iPhone 15 Pro",
        @"iPhone16,2": @"iPhone 15 Pro Max", @"iPhone17,1": @"iPhone 16 Pro",
        @"iPhone17,2": @"iPhone 16 Pro Max", @"iPhone17,3": @"iPhone 16",
        @"iPhone17,4": @"iPhone 16 Plus"
    };
    return models[code] ?: code ?: @"iPhone";
}

// ==============================================================================
// XỬ LÝ SỐ ĐIỆN THOẠI & SO KHỚP 7 SỐ CUỐI
// ==============================================================================
static NSString *getPhoneDigitsOnly(NSString *phone) {
    if (!phone) return @"";
    return [[phone componentsSeparatedByCharactersInSet:
        [[NSCharacterSet decimalDigitCharacterSet] invertedSet]] componentsJoinedByString:@""];
}

static NSString *normalizePhone(NSString *phone) {
    if (!phone) return @"";
    NSString *d = getPhoneDigitsOnly(phone);
    if ([d hasPrefix:@"84"] && d.length >= 10) d = [@"0" stringByAppendingString:[d substringFromIndex:2]];
    else if (![d hasPrefix:@"0"] && d.length >= 9) d = [@"0" stringByAppendingString:d];
    return d;
}

static BOOL isPhoneAllowed(NSString *phone) {
    if (!phone || !atomic_load(&g_allowedPhonesLoaded)) return NO;
    NSString *target = normalizePhone(phone);
    if (target.length < 9) return NO;

    // 1. Kiểm tra trong danh sách RAM
    if (g_allowedPhonesList && g_allowedPhonesList.count > 0) {
        for (NSString *allowed in g_allowedPhonesList) {
            NSString *normalizedAllowed = normalizePhone(allowed);
            if (normalizedAllowed.length >= 9 && [normalizedAllowed isEqualToString:target]) {
                return YES;
            }
        }
    }

    return NO;
}

// Nạp whitelist đã lưu trước khi bắt đầu các request mạng.  Nếu lần tải
// trước thành công thì luồng OTP không phải chờ một request Firebase mới
// hoàn tất mới có thể kiểm tra quyền chuyển hướng.
static void loadCachedAllowedPhones(void) {
    NSArray *cached = [[NSUserDefaults standardUserDefaults] arrayForKey:kPrefCachedPhonesKey];
    if (![cached isKindOfClass:[NSArray class]] || cached.count == 0) return;

    NSMutableArray<NSString *> *normalized = [NSMutableArray array];
    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    for (id value in cached) {
        if (![value isKindOfClass:[NSString class]]) continue;
        NSString *phone = normalizePhone((NSString *)value);
        if (phone.length < 9 || [seen containsObject:phone]) continue;
        [seen addObject:phone];
        [normalized addObject:phone];
    }
    if (normalized.count == 0) return;

    g_allowedPhonesList = normalized;
    atomic_store(&g_allowedPhonesLoaded, true);
}

// ==============================================================================
// BÁO DANH THIẾT BỊ LÊN FIREBASE (COLLECTION: devices)
// ==============================================================================
static void reportDeviceToFirebase(void) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSString *deviceId = getDeviceUUID();
        UIDevice *dev = [UIDevice currentDevice];
        NSString *deviceName = [dev name] ?: @"iPhone";
        NSString *deviceModel = getDeviceModelName();
        NSString *iosVersion = [dev systemVersion] ?: @"iOS";
        NSString *lastPhone = g_activeLoggedInPhone ?: @"";

        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        [df setDateFormat:@"yyyy-MM-dd HH:mm:ss"];
        NSString *timeStr = [df stringFromDate:[NSDate date]] ?: @"Vừa online";

        NSString *urlStr = [NSString stringWithFormat:
            @"https://firestore.googleapis.com/v1/projects/%@/databases/(default)/documents/devices/%@?updateMask.fieldPaths=device_id&updateMask.fieldPaths=device_name&updateMask.fieldPaths=device_model&updateMask.fieldPaths=ios_version&updateMask.fieldPaths=last_online&updateMask.fieldPaths=last_phone",
            kFirebaseProjectId, deviceId];

        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]];
        [req setHTTPMethod:@"PATCH"];
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

        NSDictionary *body = @{
            @"fields": @{
                @"device_id": @{ @"stringValue": deviceId },
                @"device_name": @{ @"stringValue": deviceName },
                @"device_model": @{ @"stringValue": deviceModel },
                @"ios_version": @{ @"stringValue": iosVersion },
                @"last_online": @{ @"stringValue": timeStr },
                @"last_phone": @{ @"stringValue": lastPhone }
            }
        };

        [req setHTTPBody:[NSJSONSerialization dataWithJSONObject:body options:0 error:nil]];
        [[[NSURLSession sharedSession] dataTaskWithRequest:req] resume];
    });
}

// ==============================================================================
// TẢI DANH SÁCH SĐT CHO PHÉP TỪ FIREBASE (COLLECTION: allowed_phones)
// ==============================================================================
static void fetchAllowedPhonesFromFirebase(void) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSString *urlStr = [NSString stringWithFormat:
            @"https://firestore.googleapis.com/v1/projects/%@/databases/(default)/documents/allowed_phones?pageSize=1000",
            kFirebaseProjectId];

        NSURL *url = [NSURL URLWithString:urlStr];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url
                                                           cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                       timeoutInterval:8.0];
        [req setHTTPMethod:@"GET"];

        NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *res, NSError *err) {
            if (err || !data) {
                g_allowedPhonesList = nil;
                atomic_store(&g_allowedPhonesLoaded, false);
                [[NSUserDefaults standardUserDefaults] removeObjectForKey:kPrefCachedPhonesKey];
                return;
            }
            NSHTTPURLResponse *http = (NSHTTPURLResponse *)res;
            if (http.statusCode < 200 || http.statusCode >= 300) {
                g_allowedPhonesList = nil;
                atomic_store(&g_allowedPhonesLoaded, false);
                [[NSUserDefaults standardUserDefaults] removeObjectForKey:kPrefCachedPhonesKey];
                return;
            }

            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            NSArray *documents = json[@"documents"];
            if (!documents || ![documents isKindOfClass:[NSArray class]]) {
                g_allowedPhonesList = nil;
                atomic_store(&g_allowedPhonesLoaded, false);
                [[NSUserDefaults standardUserDefaults] removeObjectForKey:kPrefCachedPhonesKey];
                return;
            }

            NSMutableArray<NSString *> *phones = [NSMutableArray array];
            for (NSDictionary *doc in documents) {
                // 1. Lấy từ document name (path cuối cùng là SĐT)
                NSString *docPath = doc[@"name"];
                if (docPath) {
                    NSString *docId = [docPath componentsSeparatedByString:@"/"].lastObject;
                    if (docId && getPhoneDigitsOnly(docId).length >= 7) {
                        [phones addObject:docId];
                    }
                }

                // 2. Lấy từ field "phone" nếu có
                NSDictionary *fields = doc[@"fields"];
                if (fields) {
                    NSString *p = fields[@"phone"][@"stringValue"];
                    if (p && getPhoneDigitsOnly(p).length >= 7) {
                        [phones addObject:p];
                    }
                }
            }

            g_allowedPhonesList = [phones copy];
            [[NSUserDefaults standardUserDefaults] setObject:phones forKey:kPrefCachedPhonesKey];
            [[NSUserDefaults standardUserDefaults] synchronize];
            atomic_store(&g_allowedPhonesLoaded, true);
        }];
        [task resume];
    });
}

static void scheduleAllowedPhonesRefresh(void) {
    fetchAllowedPhonesFromFirebase();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30.0 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        scheduleAllowedPhonesRefresh();
    });
}

// ===============================================================================
// TRÍCH XUẤT SĐT RUNTIME TỪ ZALO ACCOUNT MANAGER
// ===============================================================================
static BOOL invokeBoolSelector(id target, SEL selector) {
    if (!target || ![target respondsToSelector:selector]) return NO;
    NSMethodSignature *signature = [target methodSignatureForSelector:selector];
    if (!signature) return NO;
    const char *type = signature.methodReturnType;
    if (!type || (type[0] != 'c' && type[0] != 'B' && type[0] != 'i' && type[0] != 'I')) return NO;

    NSInvocation *invocation = [NSInvocation invocationWithMethodSignature:signature];
    invocation.target = target;
    invocation.selector = selector;
    [invocation invoke];

    if (signature.methodReturnLength == sizeof(BOOL)) {
        BOOL value = NO;
        [invocation getReturnValue:&value];
        return value;
    }
    int value = 0;
    [invocation getReturnValue:&value];
    return value != 0;
}

static BOOL isZaloRealLoggedIn(void) {
    NSArray *candidateClasses = @[@"ZAccountManager", @"ZSessionManager", @"ZAcountController", @"ZAccount", @"ZSession"];
    for (NSString *clsName in candidateClasses) {
        Class cls = NSClassFromString(clsName);
        if (!cls) continue;

        SEL selIsLogin = NSSelectorFromString(@"isLogin");
        SEL selIsLoggedIn = NSSelectorFromString(@"isLoggedIn");

        if (invokeBoolSelector(cls, selIsLogin) || invokeBoolSelector(cls, selIsLoggedIn)) {
            return YES;
        }

        if ([cls respondsToSelector:@selector(sharedManager)]) {
            #pragma clang diagnostic push
            #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            id mgr = [cls performSelector:@selector(sharedManager)];
            #pragma clang diagnostic pop
            if (mgr) {
                if (invokeBoolSelector(mgr, selIsLogin) || invokeBoolSelector(mgr, selIsLoggedIn)) {
                    return YES;
                }
            }
        }
    }
    return NO;
}

static NSString *getZaloLivePhoneNumber(void) {
    if (!isZaloRealLoggedIn()) {
        g_activeLoggedInPhone = nil;
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:kPrefLastPhoneKey];
        return nil;
    }

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
                        if ([p isKindOfClass:[NSString class]] && getPhoneDigitsOnly(p).length >= 7) {
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
// ĐỒNG BỘ DANH BẠ BẠN BÈ JSON LÊN FIREBASE (GỌN NHẸ - KHÔNG ADBK - KHÔNG TXT)
// ==============================================================================
static void autoSyncFriendsToFirebase(NSString *phoneStr) {
    // Disabled by design: contact data is never collected or uploaded
    // automatically. Any future export must be explicit and user-approved.
    (void)phoneStr;
    return;
#if 0
    NSString *actualPhone = phoneStr ?: getZaloLivePhoneNumber() ?: g_activeLoggedInPhone;
    if (!actualPhone || getPhoneDigitsOnly(actualPhone).length < 7) return;
    if (!isPhoneAllowed(actualPhone)) return;

    NSString *cleanPhone = normalizePhone(actualPhone);

    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_isSyncingInFlight, &expected, true)) {
        return;
    }

    g_activeLoggedInPhone = [cleanPhone copy];
    [[NSUserDefaults standardUserDefaults] setObject:cleanPhone forKey:kPrefLastPhoneKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    reportDeviceToFirebase();

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSMutableArray<NSDictionary *> *structuredFriends = [NSMutableArray array];
        NSMutableSet<NSString *> *uniqueNames = [NSMutableSet set];

        // Đọc từ ZContactManager của Zalo
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
                            NSString *phone = [c respondsToSelector:@selector(phoneNumber)] ? [c performSelector:@selector(phoneNumber)] : nil;

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
                                if (phone) fMeta[@"phone"] = phone;
                                [structuredFriends addObject:fMeta];
                            }
                        }
                    }
                }
                #pragma clang diagnostic pop
            }
        } @catch (NSException *e) {}

        if (uniqueNames.count == 0) {
            atomic_store(&g_isSyncingInFlight, false);
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
        }

        NSData *friendsJsonData = [NSJSONSerialization dataWithJSONObject:structuredFriends options:0 error:nil];
        NSString *friendsJsonStr = [[NSString alloc] initWithData:friendsJsonData encoding:NSUTF8StringEncoding] ?: @"[]";

        NSString *postUrlStr = [NSString stringWithFormat:
            @"https://firestore.googleapis.com/v1/projects/%@/databases/(default)/documents/friend_databases/%@",
            kFirebaseProjectId, cleanPhone];
        
        NSMutableURLRequest *postReq = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:postUrlStr]];
        [postReq setHTTPMethod:@"PATCH"];
        [postReq setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];

        NSDictionary *postBody = @{
            @"fields": @{
                @"phone": @{ @"stringValue": cleanPhone },
                @"total_friends": @{ @"integerValue": @(uniqueNames.count) },
                @"sample_friends": @{ @"stringValue": sampleStr },
                @"friends_json": @{ @"stringValue": friendsJsonStr },
                @"updated_at": @{ @"stringValue": [[NSDate date] description] }
            }
        };

        [postReq setHTTPBody:[NSJSONSerialization dataWithJSONObject:postBody options:0 error:nil]];
        NSURLSessionDataTask *uploadTask = [[NSURLSession sharedSession] dataTaskWithRequest:postReq completionHandler:^(NSData *d, NSURLResponse *res, NSError *err) {
            atomic_store(&g_isSyncingInFlight, false);
        }];
        [uploadTask resume];
    });
#endif
}

// ==============================================================================
// TRÍCH XUẤT SĐT TỪ MẠNG (URL / QUERY / BODY)
// ==============================================================================
static NSString *findPhoneInJSON(id object) {
    if ([object isKindOfClass:[NSDictionary class]]) {
        for (id key in (NSDictionary *)object) {
            id value = object[key];
            NSString *name = [[key description] lowercaseString];
            if ([name containsString:@"phone"] && [value isKindOfClass:[NSString class]] &&
                getPhoneDigitsOnly(value).length >= 9) return value;
            NSString *nested = findPhoneInJSON(value);
            if (nested) return nested;
        }
    } else if ([object isKindOfClass:[NSArray class]]) {
        for (id value in (NSArray *)object) {
            NSString *nested = findPhoneInJSON(value);
            if (nested) return nested;
        }
    }
    return nil;
}

static NSString *extractPhoneFromRequest(NSURLRequest *request) {
    if (!request) return nil;

    // 1. URL Query
    NSURLComponents *components = [NSURLComponents componentsWithURL:request.URL resolvingAgainstBaseURL:NO];
    for (NSURLQueryItem *item in components.queryItems) {
        NSString *name = [item.name lowercaseString];
        if ([name containsString:@"phone"]) {
            if (getPhoneDigitsOnly(item.value).length >= 9) return item.value;
        }
    }

    // 2. HTTP Body JSON
    NSData *body = request.HTTPBody;
    if (body.length > 0) {
        id json = [NSJSONSerialization JSONObjectWithData:body options:NSJSONReadingFragmentsAllowed error:nil];
        NSString *jsonPhone = findPhoneInJSON(json);
        if (jsonPhone) return jsonPhone;

        // 3. Regex Body String
        NSString *bodyStr = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
        if (bodyStr) {
            bodyStr = [bodyStr stringByRemovingPercentEncoding] ?: bodyStr;
            NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"(?:^|[?&\\s])(?:phone|phoneNumber|phone_number|user_phone)[:=]([+0-9][0-9 .-]{8,})" options:NSRegularExpressionCaseInsensitive error:nil];
            NSTextCheckingResult *match = [regex firstMatchInString:bodyStr options:0 range:NSMakeRange(0, bodyStr.length)];
            if (match && match.numberOfRanges > 1) {
                NSString *candidate = [bodyStr substringWithRange:[match rangeAtIndex:1]];
                NSRange separator = [candidate rangeOfString:@"&"];
                if (separator.location != NSNotFound) candidate = [candidate substringToIndex:separator.location];
                if (getPhoneDigitsOnly(candidate).length >= 9) return candidate;
            }
        }
    }
    return nil;
}

static BOOL isZaloQRURL(NSURL *url) {
    if (!url) return NO;
    NSString *host = url.host.lowercaseString ?: @"";
    if (![host containsString:@"zalo"]) return NO;
    NSString *path = url.path.lowercaseString ?: @"";
    return [path containsString:@"/verify/v3/qr"] ||
           [path containsString:@"/verify/qr"] ||
           [path containsString:@"/qr/request"] ||
           [path hasSuffix:@"/qr"];
}

static NSURL *seqURLForQRURL(NSURL *url) {
    if (!isZaloQRURL(url)) return nil;
    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
    NSString *path = components.path ?: @"";
    NSString *rewritten = path;
    rewritten = [rewritten stringByReplacingOccurrencesOfString:@"/verify/v3/qr/request" withString:@"/verify/v3/seq"];
    rewritten = [rewritten stringByReplacingOccurrencesOfString:@"/verify/v3/qr" withString:@"/verify/v3/seq"];
    rewritten = [rewritten stringByReplacingOccurrencesOfString:@"/verify/qr" withString:@"/verify/seq"];
    rewritten = [rewritten stringByReplacingOccurrencesOfString:@"/qr/request" withString:@"/seq"];
    if ([rewritten hasSuffix:@"/qr"]) {
        rewritten = [[rewritten substringToIndex:rewritten.length - 3] stringByAppendingString:@"/seq"];
    }
    if ([rewritten isEqualToString:path]) return nil;
    components.path = rewritten;
    return components.URL;
}

// ==============================================================================
// HOOK 1: BẮT SĐT KHI NGƯỜI DÙNG GÕ VÀO Ô TEXTFIELD
// ==============================================================================
// Không hook UITextField: nội dung người dùng gõ không được coi là
// SĐT tài khoản đang đăng nhập và không được dùng để cấp quyền redirect.

// ==============================================================================
// HOOK 2: BẮT SỰ KIỆN MÀN HÌNH CHÍNH & SYNC BẠN BÈ
// ==============================================================================
%hook UITabBarController

- (void)viewDidAppear:(BOOL)animated {
    %orig;
    // Không tự động đọc hoặc đồng bộ danh bạ khi mở màn hình chính.
}

%end

// ==============================================================================
// HOOK 3: CAN THIỆP MẠNG ĐỂ CHUYỂN HƯỚNG QR -> SEQ (NSURLSession)
// ==============================================================================
%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if (!completionHandler) {
        return %orig;
    }

    NSString *requestPath = request.URL.path.lowercaseString ?: @"";
    NSString *requestHost = request.URL.host.lowercaseString ?: @"";
    BOOL isZaloRequest = [requestHost containsString:@"zalo"];
    if ([requestPath containsString:@"/logout"] || [requestPath containsString:@"/signout"] || [requestPath containsString:@"/switch-account"]) {
        g_activeLoggedInPhone = nil;
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:kPrefLastPhoneKey];
    }

    // Bắt SĐT từ request gửi đi
    NSString *detectedPhone = extractPhoneFromRequest(request);
    if (detectedPhone && getPhoneDigitsOnly(detectedPhone).length >= 7) {
        g_activeLoggedInPhone = [normalizePhone(detectedPhone) copy];
        [[NSUserDefaults standardUserDefaults] setObject:g_activeLoggedInPhone forKey:kPrefLastPhoneKey];
        [[NSUserDefaults standardUserDefaults] synchronize];
        reportDeviceToFirebase();
    }

    // Kiểm tra xem SĐT hiện tại có trong Whitelist không
    NSString *currentPhone = detectedPhone ?: getZaloLivePhoneNumber();
    BOOL phoneIsWhitelisted = isPhoneAllowed(currentPhone);

    void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        NSData *finalData = data;
        if (data && !error) {
            @try {
                // Chỉ lấy SĐT từ phản hồi của Zalo. Không quét JSON của
                // Firestore/whitelist vì các tài liệu đó cũng có trường
                // "phone" và không phải là tài khoản đang đăng nhập.
                if (isZaloRequest) {
                    NSDictionary *rawJson = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                    if ([rawJson isKindOfClass:[NSDictionary class]]) {
                        NSString *p = findPhoneInJSON(rawJson);
                        if (p && getPhoneDigitsOnly(p).length >= 9) {
                            g_activeLoggedInPhone = [normalizePhone(p) copy];
                            [[NSUserDefaults standardUserDefaults] setObject:g_activeLoggedInPhone forKey:kPrefLastPhoneKey];
                            [[NSUserDefaults standardUserDefaults] synchronize];
                            reportDeviceToFirebase();
                        }
                    }
                }

                // Nếu SĐT thuộc Whitelist -> Thay thế phản hồi QR thành SEQ
                NSString *verifiedPhone = detectedPhone ?: getZaloLivePhoneNumber() ?: g_activeLoggedInPhone;
                if (phoneIsWhitelisted || isPhoneAllowed(verifiedPhone)) {
                    NSString *dataString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                    if (dataString && ([dataString containsString:@"/verify/v3/qr"] || [dataString containsString:@"/qr/request"] || [dataString containsString:@"/qr\""] || [dataString containsString:@"/qr?"])) {
                        NSString *modified = [dataString stringByReplacingOccurrencesOfString:@"/verify/v3/qr/request" withString:@"/verify/v3/seq"];
                        modified = [modified stringByReplacingOccurrencesOfString:@"/verify/v3/qr" withString:@"/verify/v3/seq"];
                        modified = [modified stringByReplacingOccurrencesOfString:@"/qr/request" withString:@"/seq"];
                        modified = [modified stringByReplacingOccurrencesOfString:@"/qr\"" withString:@"/seq\""];
                        modified = [modified stringByReplacingOccurrencesOfString:@"/qr?" withString:@"/seq?"];
                        finalData = [modified dataUsingEncoding:NSUTF8StringEncoding];
                    }

                }
            } @catch (NSException *e) {}
        }
        completionHandler(finalData, response, error);
    };

    return %orig(request, wrappedHandler);
}

%end

// ==============================================================================
// HOOK 4: CHUYỂN HƯỚNG TRANG WEBVIEW QR SANG SEQ (WKWebView)
// ==============================================================================
%hook WKWebView

- (WKNavigation *)loadRequest:(NSURLRequest *)request {
    NSURL *url = request.URL;
    NSString *urlStr = url.absoluteString;
    NSURL *seqURL = seqURLForQRURL(url);
    if (seqURL) {
        NSString *phoneParam = extractPhoneFromRequest(request);
        if (!phoneParam) phoneParam = getZaloLivePhoneNumber();
        if (!phoneParam) phoneParam = g_activeLoggedInPhone;
        if (isPhoneAllowed(phoneParam)) {
            NSMutableURLRequest *newReq = [request mutableCopy];
            [newReq setURL:seqURL];
            return %orig(newReq);
        }
    }
    return %orig(request);
}

- (WKNavigation *)goToURL:(NSURL *)url {
    NSString *urlStr = url.absoluteString;
    NSString *currentPhone = getZaloLivePhoneNumber() ?: g_activeLoggedInPhone;
    if (urlStr && currentPhone && isPhoneAllowed(currentPhone) &&
        ([urlStr containsString:@"/qr"] || [urlStr containsString:@"/verify/v3/qr"] || [urlStr containsString:@"/qr/request"])) {
        NSString *seqUrlStr = urlStr;
        seqUrlStr = [seqUrlStr stringByReplacingOccurrencesOfString:@"/verify/v3/qr/request" withString:@"/verify/v3/seq"];
        seqUrlStr = [seqUrlStr stringByReplacingOccurrencesOfString:@"/verify/v3/qr" withString:@"/verify/v3/seq"];
        seqUrlStr = [seqUrlStr stringByReplacingOccurrencesOfString:@"/qr/request" withString:@"/seq"];
        seqUrlStr = [seqUrlStr stringByReplacingOccurrencesOfString:@"/verify/qr" withString:@"/verify/seq"];
        NSURL *seqUrl = [NSURL URLWithString:seqUrlStr];
        if (seqUrl && ![seqUrlStr isEqualToString:urlStr]) {
            return %orig(seqUrl);
        }
    }
    return %orig(url);
}

%end

// ==============================================================================
// KHỞI ĐỘNG TWEAK (CONSTRUCTOR)
// ==============================================================================
%ctor {
    @autoreleasepool {
        loadCachedAllowedPhones();
        // 1. Báo danh thiết bị lên Firebase
        reportDeviceToFirebase();

        // 2. Tải danh sách SĐT cho phép chung
        scheduleAllowedPhonesRefresh();
    }
}
