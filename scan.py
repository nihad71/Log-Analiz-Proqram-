import os  # Qovluq yaradılması üçün
import re
import json
import csv
from selenium import webdriver
from selenium.webdriver.common.by import By
from collections import Counter
from tqdm import tqdm  # Loading bar üçün
import time

# Çıxış faylları üçün əsas qovluq
OUTPUT_FOLDER = "output_files"
os.makedirs(OUTPUT_FOLDER, exist_ok=True)  # Qovluq mövcud deyilsə, yaradılır

# Çıxış fayllarının yolları
LOG_FILE = "server_logs.txt"
FAILED_LOGINS_FILE = os.path.join(OUTPUT_FOLDER, "failed_logins.json")
LOG_ANALYSIS_TXT = os.path.join(OUTPUT_FOLDER, "log_analysis.txt")
LOG_REPORT_CSV = os.path.join(OUTPUT_FOLDER, "log_analysis.csv")
THREAT_IPS_FILE = os.path.join(OUTPUT_FOLDER, "threat_ips.json")
COMBINED_SECURITY_DATA_FILE = os.path.join(OUTPUT_FOLDER, "combined_security_data.json")

# 1. Log məlumatlarını oxuma və ayırma
def extract_log_data(log_path):
    try:
        with open(log_path, 'r') as file:
            logs = []
            for entry in tqdm(file, desc="Log qeydləri oxunur"):
                time.sleep(0.5) #süni gecikmə
                data = re.match(r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?\[(?P<timestamp>.*?)\] "(?P<method>\w+) .*? HTTP/.*?" (?P<status>\d+)', entry)
                if data:
                    logs.append(data.groupdict())
            print(f"{len(logs)} log qeydi oxundu.")
            return logs
    except FileNotFoundError:
        print(f"{log_path} faylı tapılmadı!")
        return []

# 2. Uğursuz giriş cəhdlərini analiz etmək
def find_failed_attempts(log_entries):
    failed_ips = Counter()
    for entry in tqdm(log_entries, desc="Uğursuz girişlər analiz edilir"):
        time.sleep(1) #süni gecikmə
        if entry['status'].startswith('40'):  # "40x" status kodları uğursuz cəhdləri göstərir
            failed_ips[entry['ip']] += 1
    return {ip: count for ip, count in failed_ips.items() if count >= 5}

# 3. Uğursuz girişlər və sayını mətn faylına yazmaq
def save_failed_attempts_txt(failed_attempts):
    try:
        with open(LOG_ANALYSIS_TXT, 'w', encoding='utf-8') as file:
            for ip, count in failed_attempts.items():
                file.write(f"{ip}: {count} uğursuz giriş cəhdi\n")
        print(f"Uğursuz girişlər {LOG_ANALYSIS_TXT} faylına yazıldı.")
    except Exception as e:
        print(f"Mətn faylında problem: {e}")

# 4. Log məlumatlarını CSV formatında saxlamaq
def save_logs_to_csv(log_entries, csv_path):
    try:
        with open(csv_path, 'w', newline='') as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=["ip", "timestamp", "method", "status"])
            writer.writeheader()
            for log in tqdm(log_entries, desc="Log qeydləri CSV-yə yazılır"):
                time.sleep(1) #süni gecikmə
                writer.writerow(log)
        print(f"Log məlumatları {csv_path} faylına yazıldı.")
    except Exception as e:
        print(f"CSV faylında problem yarandı: {e}")

# 5. Təhlükəli IP-lərin siyahısını əldə etmək
def fetch_threat_ips(url):
    try:
        driver = webdriver.Chrome()
        time.sleep(1.5)
        driver.get(url)
        rows = driver.find_elements(By.XPATH, "//table//tr")
        threats = {}
        for row in tqdm(rows[1:], desc="Təhlükəli IP-lər yüklənir"):
            time.sleep(1) #süni gecikmə
            cols = row.find_elements(By.TAG_NAME, "td")
            if len(cols) >= 2:
                threats[cols[0].text.strip()] = cols[1].text.strip()
        driver.quit()
        return threats
    except Exception as e:
        print(f"Təhlükəli IP-lərin yüklənməsi zamanı səhv: {e}")
        return {}

# 6. Təhlükəli IP-lərlə log məlumatlarını uyğunlaşdırmaq
def correlate_threat_ips(log_entries, threat_data):
    correlated = []
    for log in tqdm(log_entries, desc="Təhlükəli IP-lərlə uyğunlaşdırılır"):
        time.sleep(1) #süni gecikmə
        if log['ip'] in threat_data:
            log['threat_description'] = threat_data[log['ip']]
            correlated.append(log)
    return correlated

# 7. JSON fayllarını saxlamaq
def save_to_json(data, file_path):
    try:
        with open(file_path, 'w') as json_file:
            json.dump(data, json_file, indent=4)
        print(f"Məlumatlar {file_path} faylına saxlanıldı.")
    except Exception as e:
        print(f"JSON faylında problem: {e}")

# Əsas Funksiya
def main():
    print("Analiz başlandı...")

    # 1. Log məlumatlarını oxu
    logs = extract_log_data(LOG_FILE)
    if not logs:
        print("Log faylı boşdur və ya oxunmadı!")
        return

    # 2. Uğursuz giriş cəhdlərini təhlil et
    failed_attempts = find_failed_attempts(logs)
    save_to_json(failed_attempts, FAILED_LOGINS_FILE)
    save_failed_attempts_txt(failed_attempts)

    # 3. Logları CSV-yə yaz
    save_logs_to_csv(logs, LOG_REPORT_CSV)

    # 4. Təhlükəli IP məlumatlarını yüklə
    threat_url = "http://127.0.0.1:8000/"
    threat_ips = fetch_threat_ips(threat_url)
    save_to_json(threat_ips, THREAT_IPS_FILE)

    # 5. Təhlükəli IP-lərlə log məlumatlarını uyğunlaşdır
    matched_threats = correlate_threat_ips(logs, threat_ips)
    save_to_json(matched_threats, COMBINED_SECURITY_DATA_FILE)

    print("Analiz tamamlandı!")

if __name__ == "__main__":
    main()
