# Hướng dẫn build và cài clangg 2.1.1

Tweak hoạt động ngay sau khi cài và khởi động lại Zalo. Không cần nhập key, đăng ký số điện thoại hoặc cho phép thiết bị trên Firebase. Bản này không gửi báo danh thiết bị và không gọi Firebase.

## Yêu cầu

- iPhone jailbreak rootless, iOS 15 trở lên.
- Zalo với bundle ID `vn.com.vng.zingalo`.
- `mobilesubstrate` và trình quản lý gói hỗ trợ file `.deb`.

## Build bằng GitHub Actions

Đẩy mã nguồn lên repository riêng, sau đó chạy workflow **Build clangg Tweak & Deploy Sileo / Cydia APT Repo** trong tab Actions. Tải artifact **clangg_Rootless_DEB** sau khi workflow hoàn tất. Việc đẩy lên nhánh `main` hoặc `master` cũng kích hoạt workflow và triển khai APT repo.

## Build bằng Theos

Trong thư mục dự án:

```bash
make clean
make package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless
```

Gói `.deb` sẽ nằm trong `packages/`. Cài gói lên thiết bị rồi mở lại Zalo để tweak được nạp.
