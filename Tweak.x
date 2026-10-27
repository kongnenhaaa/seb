/**
 * clangg 2.1.1 - chuyển QR sang SEQ ngay khi tweak được nạp.
 * Không cần xác thực số điện thoại hoặc kết nối Firebase.
 */

#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <Foundation/Foundation.h>

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

%hook NSURLSession

- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    if (!completionHandler) return %orig;

    void (^wrappedHandler)(NSData *data, NSURLResponse *response, NSError *error) = ^(NSData *data, NSURLResponse *response, NSError *error) {
        if (data && !error && dataContainsQRPath(data)) {
            completionHandler(redirectQRDataToSEQ(data), response, error);
            return;
        }
        completionHandler(data, response, error);
    };
    return %orig(request, wrappedHandler);
}

%end

%hook WKWebView

- (WKNavigation *)loadRequest:(NSURLRequest *)request {
    NSURL *url = request.URL;
    NSString *host = url.host.lowercaseString ?: @"";
    if ([host containsString:@"zalo"]) {
        NSURL *seqUrl = redirectedSEQURL(url);
        if (seqUrl) {
            NSMutableURLRequest *newRequest = [request mutableCopy];
            newRequest.URL = seqUrl;
            return %orig(newRequest);
        }
    }
    return %orig(request);
}

- (WKNavigation *)goToURL:(NSURL *)url {
    NSURL *seqUrl = redirectedSEQURL(url);
    return %orig(seqUrl ?: url);
}

%end
