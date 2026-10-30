"""
main.py — نقطه‌ی شروع خط‌فرمان (CLI)

این فایل حالا فقط یه wrapper نازک روی core/scan_runner.py هست. همون
منطق کامل (recon → seed هانترها → اجرا → گزارش) هم از اینجا هم از
داشبورد وب صدا زده می‌شه — یه نسخه‌ی واحد از کد، دو تا نقطه‌ی ورود.

اجرا:
    cp config/scope.example.json config/scope.json     # و پرش کن با scope واقعی
    cp config/auth.example.json config/auth.json        # اختیاری، برای تست IDOR
    cp config/settings.example.json config/settings.json
    export GEMINI_API_KEY=...
    python main.py

یا به‌جاش داشبورد وب رو بالا بیار و از اونجا دکمه‌ی "شروع اسکن" رو بزن:
    cd dashboard && python app.py
"""

from core.scan_runner import run_scan

if __name__ == "__main__":
    run_scan()
    print("\nبرای دیدن داشبورد زنده (شامل تاریخچه، گزارش‌ها، و ردیاب پاداش): cd dashboard && python app.py")
