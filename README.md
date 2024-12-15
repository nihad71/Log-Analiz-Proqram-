# Log Analiz Proqram

## Təsvir

Bu proqram server log fayllarını analiz edib, müəyyən mülahizələr aparmaq üçün yaradılmışdır. Proqram log məlumatlarından IP ünvanlarını, vaxt nişanlarını, HTTP metodlarını, status kodlarını ayırır və analiz edir. Bununla yanaşı, təhlükəli IP-ləri və uğursuz giriş cəhdlərini tapıb mövcud formatlarda (JSON, CSV) saxlayır.

## Funksiyalar

### Log məlumatlarını oxumaq
**`extract_log_data`**: Log faylından məlumatları oxuyur və struktur formatda saxlayır.

### Uğursuz giriş cəhdlərinin analizi
**`find_failed_attempts`**: Uğursuz giriş cəhdləri edən IP-ləri və onların tezliyini hesablayır.

### Logları CSV formatında saxlamaq
**`save_logs_to_csv`**: Log məlumatlarını CSV faylına yazır.

### Təhlükəli IP-ləri yükləmək
**`fetch_threat_ips`**: URL vasitəsilə təhlükəli IP-lər haqqında məlumatları toplayır.

### Təhlükəli IP-lərlə log məlumatlarını uyğunlaşdırmaq
**`correlate_threat_ips`**: Log məlumatlarını təhlükəli IP-lər siyahısı ilə müqayisə edib uyğunluqları saxlayır.

### Məlumatları JSON formatında saxlamaq
**`save_to_json`**: Verilənləri JSON faylı kimi saxlayır.

## Tələblər

Proqramı şəbəkədə istifadə etmək üçün aşağıdakı proqram paketləri lazımdır:

- Python 3.7+
- selenium kitabxanası (Təhlükəli IP-ləri yükləmək üçün)
- tqdm kitabxanası (Proqress bar üçün)
- collections.Counter (Statistik analiz üçün)

### Python paketlərini qurmaq:
```
pip install selenium tqdm
```
### Selenium üçün brauzer sürücüsü

Selenium üçün uyğun ChromeDriver yükləyib sistem çevrəsindəki `PATH`-a əlavə etməlisiniz.

## Faydalanılan Fayllar

Proqram aşağıdakı çıxış fayllarını yarada bilər:

- **unsuccessful_logins.json**: 5-dən çox uğursuz giriş cəhdi olan IP-lərin siyahısı.
- **logs_report.csv**: Log məlumatlarının CSV formatı.
- **detected_threat_ips.json**: Təhlükəli IP-lərin siyahısı.
- **matched_threat_logs.json**: Təhlükəli IP-lərlə uyğun log qeydləri.

Bütün fayllar avtomatik olaraq `output_files` qovluğundan tapıla bilər.

## İstifadə Qaydaları

1. Log faylını `server_logs.txt` olaraq proqramla eyni qovluqda saxlayın.
2. `main()` funksiyasını işə salmaq üçün:
   
    ```bash
    python <program_adı>.py
    ```
4. Təhlil tamamlandıqda, nəticə faylları `output_files` qovluğundan yoxlaya bilərsiniz.

## Struktur

Proqram çıxış fayllarını bir qovluqda toplamaq üçün "output_files" adlı bir qovluq yaradır. Həmin qovluq şrahiti saxlayan mülahizə şraiti yaratmaq üçün istifadə olunur.

## Problem Giderme

### Log faylı tapılmadı:
`server_logs.txt` faylı mövcud olub-olmadığını yoxlayın.

### ChromeDriver problemi:
Selenium kitabxanası üçün uyğun versiyalı ChromeDriver yükləyin.

Brauzer versiyanızı yoxlayıb uyğun sürücünü [buradan yükləyin](https://sites.google.com/a/chromium.org/chromedriver/).
