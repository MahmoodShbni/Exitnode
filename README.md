# relay — یک route-optimizer سبک شبیه ExitLag (نسخه‌ی اسکلت)

فقط ترافیک **UDP** پروسس بازی (بر اساس IP سرور بازی) را از VPS شما عبور می‌دهد.
ترافیک **TCP** و بقیه‌ی برنامه‌ها اصلاً لمس نمی‌شوند و مستقیم از اینترنت کلاینت می‌روند.

```
بازی (cs2.exe) ──UDP──▶ WinDivert (capture) ──encapsulated──▶ VPS (Linux) ──raw UDP──▶ سرور CS2
بازی (cs2.exe) ◀─inject── WinDivert            ◀──encapsulated── VPS           ◀──raw UDP── سرور CS2
```

بدون رمزنگاری و بدون handshake. فقط ۱۵ بایت هدر برای مسیریابی و حذف پکت‌های تکراری (dedup).

## ساختار

| فایل | نقش |
|------|------|
| `proto/` | فرمت سیم + پنجره‌ی dedup (مشترک) |
| `server/` | forwarder سمت لینوکس (VPS) |
| `client/` | کلاینت ویندوزی روی WinDivert |

## بیلد

به **Go 1.23 یا بالاتر** نیاز است. اولین بار وابستگی‌ها را resolve کن (go.sum می‌سازد):
```
go mod tidy
```

سرور (روی هر سیستمی قابل کراس‌کامپایل است):
```
GOOS=linux GOARCH=amd64 go build -o relay-server ./server
```

کلاینت ویندوز:
```
GOOS=windows GOARCH=amd64 go build -o relay-client.exe ./client
```

کنار `relay-client.exe` باید فایل‌های **WinDivert نسخه‌ی 2.x** باشند
(از ریلیز رسمی WinDivert 2.2): `WinDivert.dll` و `WinDivert64.sys`.
کلاینت با binding ‏`github.com/imgk/divert-go` کار می‌کند که فقط با WinDivert 2.x
سازگار است؛ نسخه‌ی 1.x باعث panic می‌شود. کلاینت باید **با دسترسی Administrator** اجرا شود.

## اجرا

روی VPS:
```
./relay-server -listen :51820 -redundancy 1
```

روی ویندوز (CMD/PowerShell با Run as Administrator):
```
relay-client.exe -relay <VPS_IP>:51820 -game <CS2_SERVER_IP> -redundancy 2
```

`-redundancy 2` یعنی هر پکت دو بار به سمت VPS فرستاده می‌شود؛ سمت گیرنده تکراری را
با seq دور می‌اندازد. این همان مکانیزمی است که packet loss را روی لگ بین‌المللی
(کلاینت→VPS) می‌پوشاند. مصرف پهنای باند هم به همان نسبت بالا می‌رود.

## قبل از هر چیز: اندازه‌گیری کن

با `WinMTR` مسیر فعلی‌ات به IP سرور CS2 را ببین، و دوباره با مسیر از طریق VPS.
اگر VPS روی مسیر بهتری به دیتاسنتر هدف نیست، این کل زحمت پینگت را **بدتر** می‌کند نه بهتر.
exit-node باید از نظر شبکه به دیتاسنتر سرور بازی نزدیک باشد.

## محدودیت‌های این نسخه (عمداً ساده نگه داشته شده)

- **IPv4 only.** برای IPv6 باید buildInbound و فیلتر گسترش یابد.
- **تک‌رله / single exit.** کلاینت به یک VPS وصل می‌شود. multipath واقعی روی چند مسیرِ
  مجزا که همه به یک exit برسند، به یک توپولوژی زنجیره‌ای (entry→exit) نیاز دارد؛ اگر هر
  مسیر مستقیماً به CS2 برود، سرور بازی پکت تکراری می‌گیرد. ساختار dedup اینجا آماده است؛
  برای multipath کافی است یک VPS را entry و یکی را exit کنی و همین پروتکل را بین آن‌ها سوار کنی.
- **process-awareness:** فیلتر فعلاً بر اساس IP سرور بازی است. برای تطبیق دقیق با پورت‌های
  باز `cs2.exe`، از `GetExtendedUdpTable` پورت‌های پروسس را پیدا کن و فیلتر را به آن‌ها محدود کن.
- **UDP checksum = 0** در پکت تزریقی (مجاز در IPv4). اگر جایی پکت‌ها افتادند، چک‌سام واقعی UDP را حساب کن.

## آنتی‌چیت

WinDivert یک درایور packet-manipulation عمومی است. CS2 از VAC استفاده می‌کند که نسبت به
بعضی anti-cheatهای kernel-level تهاجمی‌تر سهل‌گیرتر است، اما حضور این درایور یک ریسک تئوریک
است که خودت باید بسنجی. این یکی از دلایلی است که سرویس‌هایی مثل ExitLag درایور اختصاصی
تست‌شده‌ی خودشان را دارند.
