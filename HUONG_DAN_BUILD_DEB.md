# HƯỚNG DẪN BIÊN DỊCH FILE .DEB HOÀN CHỈNH CÓ BẢN QUYỀN

Toàn bộ mã nguồn trong thư mục `C:\Users\congn\Pictures\seb` đã được cấu hình sẵn 100% để kết nối với Web Firebase `seq-qr` của bạn.

---

### Cách 1: Tự động Build bằng GitHub Actions (Khuyên dùng - 1 Phút có file .deb)

1. Tạo 1 Repository mới trên GitHub (Chọn **Private** để giấu mã nguồn).
2. Đẩy toàn bộ các file trong thư mục `C:\Users\congn\Pictures\seb` này lên Repository đó:
   ```bash
   cd C:\Users\congn\Pictures\seb
   git init
   git add .
   git commit -m "Build Zalo SEQ Tweak clangg"
   git branch -M main
   git remote add origin https://github.com/<tai-khoan-cua-ban>/<ten-repo>.git
   git push -u origin main
   ```
3. Vào tab **Actions** trên GitHub -> Bạn sẽ thấy tiến trình Build tự động chạy.
4. Sau khi workflow hoàn tất, vào mục **Artifacts** tải gói **`clangg_Rootless_DEB`** phiên bản **1.1.7**.

---

### Cách 2: Biên dịch trực tiếp nếu có máy Mac / iPhone Jailbreak

Chạy lệnh trong thư mục này:
```bash
make clean
make package FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=rootless
```
File `.deb` hoàn thiện sẽ nằm trong thư mục `packages/`.
