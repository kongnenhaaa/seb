/**
 * ==============================================================================
 * TWEAK SEB - ZALO SEQ REDIRECT & THIẾT BỊ HOẠT ĐỘNG
 * Phiên bản: 2.1.0 (Single-document lookup + cache)
 * ==============================================================================
 * Logic hoạt động:
 * 1. KHÔNG KEY BẢN QUYỀN, KHÔNG USER, KHÔNG ADBK, KHÔNG TXT.
 * 2. Tự động báo danh thiết bị đã cài Seb lên Web Firebase (Collection: devices).
 * 3. Chỉ đọc đúng 1 document SĐT từ Firebase (Collection: allowed_phones).
 * 4. Cache kết quả hợp lệ 6 giờ, chống request trùng và backoff khi gặp 429.
 * 5. Chuẩn hóa đầu số 0, 84, +84 và chặn QR chuyển sang SEQ khi được phép.
 * ==============================================================================
 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/utsname.h>
#import <stdatomic.h>
#include <dlfcn.h>

static NSString *const kFirebaseProjectId = @"qr-seb";
static NSString *const kPrefPhoneCacheKey = @"kSebPhoneValidationCache_v3";
static NSString *const kPrefLastPhoneKey = @"kSebLastPhone_v3";
static NSString *const kPrefLastDeviceReportKey = @"kSebLastDeviceReport_v3";
static NSString *const kPrefLastReportedPhoneKey = @"kSebLastReportedPhone_v3";
static const NSTimeInterval kAllowedCacheTTL = 6.0 * 60.0 * 60.0;
static const NSTimeInterval kDeniedCacheTTL = 10.0 * 60.0;
static const NSTimeInterval kStaleAllowedTTL = 24.0 * 60.0 * 60.0;
static const NSTimeInterval kDeviceReportInterval = 6.0 * 60.0 * 60.0;

// ==============================================================================
// TRẠNG THÁI TOÀN CỤC (GLOBAL STATE)
// ==============================================================================
static NSString *g_activeLoggedInPhone = nil;
static NSMutableDictionary<NSString *, NSMutableArray *> *g_phoneCheckCallbacks = nil;
static NSTimeInterval g_serverBackoffUntil = 0;
static NSUInteger g_phonePreflightGeneration = 0;

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

static BOOL isValidPhoneForLookup(NSString *phone) {
    NSString *normalized = normalizePhone(phone);
    return normalized.length >= 9 && normalized.length <= 15;
}

static void rememberActivePhone(NSString *phone) {
    NSString *normalized = normalizePhone(phone);
    if (!isValidPhoneForLookup(normalized)) return;
    if ([g_activeLoggedInPhone isEqualToString:normalized]) return;

    g_activeLoggedInPhone = [normalized copy];
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:g_activeLoggedInPhone forKey:kPrefLastPhoneKey];
    [defaults synchronize];
}

static BOOL cachedPhoneStatus(NSString *phone, BOOL allowStale, BOOL *found) {
    if (found) *found = NO;
    NSString *normalized = normalizePhone(phone);
    if (!isValidPhoneForLookup(normalized)) return NO;

    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSDictionary *entry = nil;
    @synchronized (defaults) {
        NSDictionary *cache = [defaults dictionaryForKey:kPrefPhoneCacheKey];
        id value = cache[normalized];
        if ([value isKindOfClass:[NSDictionary class]]) entry = value;
    }
    if (!entry) return NO;

    NSNumber *allowedValue = entry[@"allowed"];
    NSNumber *checkedAtValue = entry[@"checked_at"];
    if (![allowedValue isKindOfClass:[NSNumber class]] || ![checkedAtValue isKindOfClass:[NSNumber class]]) return NO;

    BOOL allowed = allowedValue.boolValue;
    NSTimeInterval age = [[NSDate date] timeIntervalSince1970] - checkedAtValue.doubleValue;
    NSTimeInterval ttl = allowed ? (allowStale ? kStaleAllowedTTL : kAllowedCacheTTL) : kDeniedCacheTTL;
    if (age < 0 || age > ttl) return NO;

    if (found) *found = YES;
    return allowed;
}

static void storePhoneStatus(NSString *phone, BOOL allowed) {
    NSString *normalized = normalizePhone(phone);
    if (!isValidPhoneForLookup(normalized)) return;

    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    @synchronized (defaults) {
        NSMutableDictionary *cache = [[defaults dictionaryForKey:kPrefPhoneCacheKey] mutableCopy] ?: [NSMutableDictionary dictionary];
        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
        for (NSString *key in [cache.allKeys copy]) {
            NSDictionary *entry = [cache[key] isKindOfClass:[NSDictionary class]] ? cache[key] : nil;
            NSNumber *checkedAt = entry[@"checked_at"];
            if (!checkedAt || now - checkedAt.doubleValue > 30.0 * 24.0 * 60.0 * 60.0) {
                [cache removeObjectForKey:key];
            }
        }
        cache[normalized] = @{ @"allowed": @(allowed), @"checked_at": @(now) };
        [defaults setObject:cache forKey:kPrefPhoneCacheKey];
        [defaults synchronize];
    }
}

// ==============================================================================
// BÁO DANH THIẾT BỊ LÊN FIREBASE (COLLECTION: devices)
// ==============================================================================
static void reportDeviceToFirebase(void) {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    NSTimeInterval lastReport = [defaults doubleForKey:kPrefLastDeviceReportKey];
    NSString *currentPhone = g_activeLoggedInPhone ?: [defaults stringForKey:kPrefLastPhoneKey] ?: @"";
    NSString *lastReportedPhone = [defaults stringForKey:kPrefLastReportedPhoneKey] ?: @"";

    if (now - lastReport < kDeviceReportInterval && [currentPhone isEqualToString:lastReportedPhone]) return;
    [defaults setDouble:now forKey:kPrefLastDeviceReportKey];
    [defaults setObject:currentPhone forKey:kPrefLastReportedPhoneKey];
    [defaults synchronize];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        NSString *deviceId = getDeviceUUID();
        UIDevice *dev = [UIDevice currentDevice];
        NSString *deviceName = [dev name] ?: @"iPhone";
        NSString *deviceModel = getDeviceModelName();
        NSString *iosVersion = [dev systemVersion] ?: @"iOS";
        NSString *lastPhone = currentPhone;

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
// KIỂM TRA ĐÚNG 1 DOCUMENT SĐT + CACHE/COALESCE/BACKOFF
// ==============================================================================
static void finishPhoneCheck(NSString *phone, BOOL allowed) {
    NSArray *callbacks = nil;
    @synchronized (g_phoneCheckCallbacks) {
        callbacks = [g_phoneCheckCallbacks[phone] copy];
        [g_phoneCheckCallbacks removeObjectForKey:phone];
    }
    for (id callbackObject in callbacks) {
        void (^callback)(BOOL) = callbackObject;
        callback(allowed);
    }
}

static void checkPhoneAllowed(NSString *phone, void (^completion)(BOOL allowed)) {
    NSString *normalized = normalizePhone(phone);
    void (^safeCompletion)(BOOL) = completion ? [completion copy] : ^(BOOL allowed) {};
    if (!isValidPhoneForLookup(normalized)) {
        safeCompletion(NO);
        return;
    }

    BOOL cached = NO;
    BOOL hasFreshCache = NO;
    cached = cachedPhoneStatus(normalized, NO, &hasFreshCache);
    if (hasFreshCache) {
        safeCompletion(cached);
        return;
    }

    @synchronized (g_phoneCheckCallbacks) {
        NSMutableArray *callbacks = g_phoneCheckCallbacks[normalized];
        if (callbacks) {
            [callbacks addObject:safeCompletion];
            return;
        }
        g_phoneCheckCallbacks[normalized] = [NSMutableArray arrayWithObject:safeCompletion];
    }

    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    BOOL backoffActive = NO;
    @synchronized (g_phoneCheckCallbacks) {
        backoffActive = now < g_serverBackoffUntil;
    }
    if (backoffActive) {
        BOOL hasStaleCache = NO;
        BOOL staleAllowed = cachedPhoneStatus(normalized, YES, &hasStaleCache);
        finishPhoneCheck(normalized, hasStaleCache ? staleAllowed : NO);
        return;
    }

    NSString *urlStr = [NSString stringWithFormat:
        @"https://firestore.googleapis.com/v1/projects/%@/databases/(default)/documents/allowed_phones/%@",
        kFirebaseProjectId, normalized];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlStr]
                                                           cachePolicy:NSURLRequestUseProtocolCachePolicy
                                                       timeoutInterval:6.0];
    [request setHTTPMethod:@"GET"];
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];

    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSHTTPURLResponse *http = (NSHTTPURLResponse *)response;
        NSInteger statusCode = http.statusCode;
        BOOL definitive = NO;
        BOOL allowed = NO;

        if (!error && statusCode == 200 && data.length > 0) {
            NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            NSDictionary *fields = [json isKindOfClass:[NSDictionary class]] ? json[@"fields"] : nil;
            NSString *status = fields[@"status"][@"stringValue"] ?: @"active";
            NSNumber *enabled = fields[@"enabled"][@"booleanValue"];
            allowed = ![status isEqualToString:@"blocked"] &&
                      ![status isEqualToString:@"inactive"] &&
                      (!enabled || enabled.boolValue);
            definitive = YES;
        } else if (!error && statusCode == 404) {
            definitive = YES;
            allowed = NO;
        }

        if (definitive) {
            storePhoneStatus(normalized, allowed);
            @synchronized (g_phoneCheckCallbacks) {
                g_serverBackoffUntil = 0;
            }
            finishPhoneCheck(normalized, allowed);
            return;
        }

        NSTimeInterval retryDelay = (statusCode == 429) ? 15.0 * 60.0 : 60.0;
        @synchronized (g_phoneCheckCallbacks) {
            g_serverBackoffUntil = [[NSDate date] timeIntervalSince1970] + retryDelay;
        }
        BOOL hasStaleCache = NO;
        BOOL staleAllowed = cachedPhoneStatus(normalized, YES, &hasStaleCache);
        finishPhoneCheck(normalized, hasStaleCache ? staleAllowed : NO);
    }];
    [task resume];
}

// ==============================================================================
// TRÍCH XUẤT SĐT RUNTIME TỪ ZALO ACCOUNT MANAGER
// ==============================================================================
static BOOL isZaloRealLoggedIn(void) {
    NSArray *candidateClasses = @[@"ZAccountManager", @"ZSessionManager", @"ZAcountController", @"ZAccount", @"ZSession"];
    for (NSString *clsName in candidateClasses) {
        Class cls = NSClassFromString(clsName);
        if (!cls) continue;

        SEL selIsLogin = NSSelectorFromString(@"isLogin");
        SEL selIsLoggedIn = NSSelectorFromString(@"isLoggedIn");

        if ([cls respondsToSelector:selIsLogin] || [cls respondsToSelector:selIsLoggedIn]) {
            return YES;
        }

        if ([cls respondsToSelector:@selector(sharedManager)]) {
            #pragma clang diagnostic push
            #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
            id mgr = [cls performSelector:@selector(sharedManager)];
            #pragma clang diagnostic pop
            if (mgr) {
                if ([mgr respondsToSelector:selIsLogin] || [mgr respondsToSelector:selIsLoggedIn]) {
                    return YES;
                }
            }
        }
    }
    return NO;
}

static NSString *getZaloLivePhoneNumber(void) {
    if (!isZaloRealLoggedIn()) return nil;

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
// TRÍCH XUẤT SĐT TỪ MẠNG (URL / QUERY / BODY / JSON)
// ==============================================================================
static NSString *findPhoneInJSON(id object) {
    if (!object) return nil;
    if ([object isKindOfClass:[NSDictionary class]]) {
        for (id key in (NSDictionary *)object) {
            id value = object[key];
            NSString *name = [[key description] lowercaseString];
            if ([name containsString:@"phone"] && [value isKindOfClass:[NSString class]] &&
                getPhoneDigitsOnly(value).length >= 7) return value;
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
            if (getPhoneDigitsOnly(item.value).length >= 7) return item.value;
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
            NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern:@"(?:^|[?&\\s])(?:phone|phoneNumber|phone_number|user_phone)[:=]([+0-9][0-9 .-]{6,})" options:NSRegularExpressionCaseInsensitive error:nil];
            NSTextCheckingResult *match = [regex firstMatchInString:bodyStr options:0 range:NSMakeRange(0, bodyStr.length)];
            if (match && match.numberOfRanges > 1) {
                NSString *candidate = [bodyStr substringWithRange:[match rangeAtIndex:1]];
                NSRange separator = [candidate rangeOfString:@"&"];
                if (separator.location != NSNotFound) candidate = [candidate substringToIndex:separator.location];
                if (getPhoneDigitsOnly(candidate).length >= 7) return candidate;
            }
        }
    }
    return nil;
}

static BOOL dataContainsQRPath(NSData *data) {
    if (!data.length) return NO;
    NSString *value = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!value) return NO;
    return [value containsString:@"/verify/v3/qr"] ||
           [value containsString:@"/qr/request"] ||
           [value containsString:@"/qr\""] ||
           [value containsString:@"/qr?"] ||
           [value containsString:@"/verify/qr"];
}

static NSData *redirectQRDataToSEQ(NSData *data) {
    NSString *value = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!value) return data;
    NSString *modified = [value stringByReplacingOccurrencesOfString:@"/verify/v3/qr/request" withString:@"/verify/v3/seq"];
    modified = [modified stringByReplacingOccurrencesOfString:@"/verify/v3/qr" withString:@"/verify/v3/seq"];
    modified = [modified stringByReplacingOccurrencesOfString:@"/verify/qr" withString:@"/verify/seq"];
    modified = [modified stringByReplacingOccurrencesOfString:@"/qr/request" withString:@"/seq"];
    modified = [modified stringByReplacingOccurrencesOfString:@"/qr\"" withString:@"/seq\""];
    modified = [modified stringByReplacingOccurrencesOfString:@"/qr?" withString:@"/seq?"];
    return [modified dataUsingEncoding:NSUTF8StringEncoding] ?: data;
}

static NSURL *redirectedSEQURL(NSURL *url) {
    NSString *urlStr = url.absoluteString;
    if (!urlStr) return nil;
    NSString *seqUrlStr = [urlStr stringByReplacingOccurrencesOfString:@"/verify/v3/qr/request" withString:@"/verify/v3/seq"];
    seqUrlStr = [seqUrlStr stringByReplacingOccurrencesOfString:@"/verify/v3/qr" withString:@"/verify/v3/seq"];
    seqUrlStr = [seqUrlStr stringByReplacingOccurrencesOfString:@"/qr/request" withString:@"/seq"];
    seqUrlStr = [seqUrlStr stringByReplacingOccurrencesOfString:@"/verify/qr" withString:@"/verify/seq"];

    if ([seqUrlStr isEqualToString:urlStr]) {
        NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
        NSString *path = components.path;
        if ([path hasSuffix:@"/qr"]) {
            components.path = [[path substringToIndex:path.length - 3] stringByAppendingString:@"/seq"];
            seqUrlStr = components.URL.absoluteString;
        }
    }
    if ([seqUrlStr isEqualToString:urlStr]) return nil;
    return [NSURL URLWithString:seqUrlStr];
}

// ==============================================================================
// HOOK 1: BẮT SĐT KHI NGƯỜI DÙNG GÕ VÀO Ô TEXTFIELD
// ==============================================================================
%hook UITextField

- (void)setText:(NSString *)text {
    %orig(text);
    if (text && text.length >= 9) {
        NSString *digits = getPhoneDigitsOnly(text);
        if (digits.length >= 9 && digits.length <= 15) {
            rememberActivePhone(digits);
            NSString *phoneToCheck = [g_activeLoggedInPhone copy];
            NSUInteger generation = ++g_phonePreflightGeneration;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(750 * NSEC_PER_MSEC)), dispatch_get_main_queue(), ^{
                if (generation == g_phonePreflightGeneration && [g_activeLoggedInPhone isEqualToString:phoneToCheck]) {
                    checkPhoneAllowed(phoneToCheck, nil);
                }
            });
        }
    }
}

%end

// ==============================================================================
// HOOK 2: CAN THIỆP MẠNG ĐỂ CHUYỂN HƯỚNG QR -> SEQ (NSURLSession)
// ==============================================================================
%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if (!completionHandler) {
        return %orig;
    }

    NSString *requestHost = request.URL.host.lowercaseString ?: @"";
    if ([requestHost isEqualToString:@"firestore.googleapis.com"]) {
        return %orig;
    }

    NSString *requestPath = request.URL.path.lowercaseString ?: @"";
    if ([requestPath containsString:@"/logout"] || [requestPath containsString:@"/signout"] || [requestPath containsString:@"/switch-account"]) {
        g_activeLoggedInPhone = nil;
        g_phonePreflightGeneration++;
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:kPrefLastPhoneKey];
    }

    // Bắt SĐT từ request gửi đi
    NSString *detectedPhone = extractPhoneFromRequest(request);
    if (detectedPhone && getPhoneDigitsOnly(detectedPhone).length >= 9) {
        rememberActivePhone(detectedPhone);
    }

    void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data && !error) {
            @try {
                // Trích xuất SĐT từ JSON response
                NSDictionary *rawJson = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                if ([rawJson isKindOfClass:[NSDictionary class]]) {
                    NSString *p = findPhoneInJSON(rawJson);
                    if (p && getPhoneDigitsOnly(p).length >= 9) {
                        rememberActivePhone(p);
                    }
                }

                NSString *currentPhone = g_activeLoggedInPhone ?: detectedPhone ?: [[NSUserDefaults standardUserDefaults] stringForKey:kPrefLastPhoneKey] ?: getZaloLivePhoneNumber();
                if (dataContainsQRPath(data)) {
                    checkPhoneAllowed(currentPhone, ^(BOOL allowed) {
                        completionHandler(allowed ? redirectQRDataToSEQ(data) : data, response, error);
                    });
                    return;
                }
            } @catch (NSException *e) {}
        }
        completionHandler(data, response, error);
    };

    return %orig(request, wrappedHandler);
}

%end

// ==============================================================================
// HOOK 3: CHUYỂN HƯỚNG TRANG WEBVIEW QR SANG SEQ (WKWebView)
// ==============================================================================
%hook WKWebView

- (WKNavigation *)loadRequest:(NSURLRequest *)request {
    NSURL *url = request.URL;
    NSString *urlStr = url.absoluteString;
    NSString *host = url.host.lowercaseString ?: @"";

    if ([host containsString:@"zalo.me"] || [host containsString:@"zaloapp.com"] || [host containsString:@"zalo"]) {
        if ([urlStr containsString:@"/qr"] || [urlStr containsString:@"/verify/v3/qr"] || [urlStr containsString:@"/qr/request"] || [urlStr containsString:@"/verify/qr"]) {
            NSString *phoneParam = extractPhoneFromRequest(request);
            if (!isValidPhoneForLookup(phoneParam)) {
                phoneParam = g_activeLoggedInPhone ?: [[NSUserDefaults standardUserDefaults] stringForKey:kPrefLastPhoneKey] ?: getZaloLivePhoneNumber();
            }
            rememberActivePhone(phoneParam);

            NSURL *seqUrl = redirectedSEQURL(url);
            BOOL hasFreshCache = NO;
            BOOL allowed = cachedPhoneStatus(phoneParam, NO, &hasFreshCache);
            if (seqUrl && hasFreshCache && allowed) {
                NSMutableURLRequest *newRequest = [request mutableCopy];
                newRequest.URL = seqUrl;
                return %orig(newRequest);
            }

            if (seqUrl && !hasFreshCache) {
                __weak WKWebView *weakWebView = self;
                NSURLRequest *originalRequest = [request copy];
                checkPhoneAllowed(phoneParam, ^(BOOL isAllowed) {
                    if (!isAllowed) return;
                    dispatch_async(dispatch_get_main_queue(), ^{
                        WKWebView *webView = weakWebView;
                        if (!webView) return;
                        NSMutableURLRequest *newRequest = [originalRequest mutableCopy];
                        newRequest.URL = seqUrl;
                        [webView loadRequest:newRequest];
                    });
                });
            }
        }
    }
    return %orig(request);
}

- (WKNavigation *)goToURL:(NSURL *)url {
    NSString *urlStr = url.absoluteString;
    if (urlStr && ([urlStr containsString:@"/qr"] || [urlStr containsString:@"/verify/v3/qr"] || [urlStr containsString:@"/qr/request"])) {
        NSString *phoneParam = g_activeLoggedInPhone ?: [[NSUserDefaults standardUserDefaults] stringForKey:kPrefLastPhoneKey] ?: getZaloLivePhoneNumber();
        NSURL *seqUrl = redirectedSEQURL(url);
        BOOL hasFreshCache = NO;
        BOOL allowed = cachedPhoneStatus(phoneParam, NO, &hasFreshCache);
        if (seqUrl && hasFreshCache && allowed) {
            return %orig(seqUrl);
        }

        if (seqUrl && !hasFreshCache) {
            __weak WKWebView *weakWebView = self;
            checkPhoneAllowed(phoneParam, ^(BOOL isAllowed) {
                if (!isAllowed) return;
                dispatch_async(dispatch_get_main_queue(), ^{
                    [weakWebView loadRequest:[NSURLRequest requestWithURL:seqUrl]];
                });
            });
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
        g_phoneCheckCallbacks = [NSMutableDictionary dictionary];
        NSString *lastPhone = [[NSUserDefaults standardUserDefaults] stringForKey:kPrefLastPhoneKey];
        if (isValidPhoneForLookup(lastPhone)) g_activeLoggedInPhone = [normalizePhone(lastPhone) copy];

        // Báo danh tối đa 1 lần/6 giờ hoặc khi SĐT thay đổi.
        reportDeviceToFirebase();
        [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidBecomeActiveNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification * _Nonnull note) {
            reportDeviceToFirebase();
        }];
    }
}
