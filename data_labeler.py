# data_labeler.py
import os
import json
from datetime import datetime

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
EXPORT_FILE = os.path.join(DATA_DIR, "suspicious_export.json")
LABELED_FILE = os.path.join(DATA_DIR, "obscura_labeled.json")

os.makedirs(DATA_DIR, exist_ok=True)

VALID_LABELS = ["safe", "suspicious", "malicious", "unknown"]

def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_json(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            return True
    except Exception as e:
        print("Ошибка сохранения:", e)
        return False

def merge_new(exported, labeled):
    # Build key set for dedupe: ip + timestamp (if timestamp present) or ip+process
    keys = set()
    for rec in labeled:
        k = (rec.get("ip"), rec.get("timestamp")) if rec.get("timestamp") else (rec.get("ip"), rec.get("process"))
        keys.add(k)
    added = 0
    for rec in exported:
        k = (rec.get("ip"), rec.get("timestamp")) if rec.get("timestamp") else (rec.get("ip"), rec.get("process"))
        if k not in keys:
            # add label field default None
            rec.setdefault("label", None)
            labeled.append(rec)
            keys.add(k)
            added += 1
    return added, labeled

def pretty_show(rec, idx):
    print(f"[{idx}] {rec.get('timestamp','-')} IP:{rec.get('ip','-')} Country:{rec.get('country','-')} Process:{rec.get('process','-')} PID:{rec.get('pid','-')} Port:{rec.get('port','-')} Threat:{rec.get('threat_score','-')} Label:{rec.get('label')}")

def main():
    print("Загрузка размеченных записей...")
    labeled = load_json(LABELED_FILE)
    print(f"Загружено размеченных: {len(labeled)}")

    print("Загрузка экспортированных подозрительных записей...")
    exported = load_json(EXPORT_FILE)
    print(f"Загружено экспортированных: {len(exported)}")

    added, labeled = merge_new(exported, labeled)
    if added:
        print(f"Добавлено новых записей: {added}")
        save_json(LABELED_FILE, labeled)
    else:
        print("Новых записей не найдено.")

    print("\nКоманды: list, show <idx>, label <idx> <safe|suspicious|malicious|unknown>, save, quit")
    while True:
        cmd = input("> ").strip()
        if not cmd:
            continue
        parts = cmd.split()
        cmd0 = parts[0].lower()
        if cmd0 == "list":
            for i, rec in enumerate(labeled):
                print(f"{i}: {rec.get('timestamp','-')} IP:{rec.get('ip','-')} Label:{rec.get('label')}")
        elif cmd0 == "show":
            if len(parts) < 2:
                print("Укажи индекс: show 5")
                continue
            try:
                idx = int(parts[1])
                if 0 <= idx < len(labeled):
                    pretty_show(labeled[idx], idx)
                else:
                    print("Индекс вне диапазона")
            except ValueError:
                print("Индекс должен быть числом")
        elif cmd0 == "label":
            if len(parts) < 3:
                print("Использование: label <idx> <label>")
                continue
            try:
                idx = int(parts[1])
                label = parts[2].lower()
                if label not in VALID_LABELS:
                    print("Неверная метка. Допустимо:", VALID_LABELS)
                    continue
                if 0 <= idx < len(labeled):
                    labeled[idx]["label"] = label
                    labeled[idx].setdefault("labeled_at", now_ts())
                    print(f"Запись {idx} помечена как {label}")
                else:
                    print("Индекс вне диапазона")
            except ValueError:
                print("Индекс должен быть числом")
        elif cmd0 == "save":
            ok = save_json(LABELED_FILE, labeled)
            print("Сохранено." if ok else "Ошибка при сохранении.")
        elif cmd0 == "quit" or cmd0 == "exit":
            ans = input("Сохранить перед выходом? (y/n) ").strip().lower()
            if ans == "y":
                save_json(LABELED_FILE, labeled)
            print("Выход.")
            break
        else:
            print("Неизвестная команда. Команды: list, show <idx>, label <idx> <label>, save, quit")

if __name__ == "__main__":
    main()
