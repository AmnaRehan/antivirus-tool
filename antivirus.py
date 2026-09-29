import os
import hashlib
import shutil

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".vbs",
    ".vbe", ".ps1", ".scr", ".msi", ".jar"
}

SUSPICIOUS_NAMES = {
    "keylogger",
    "password_stealer",
    "ransom",
    "ransomware",
    "trojan",
    "virus",
    "malware",
    "crack",
    "payload",
    "hack"
}

SUSPICIOUS_CONTENT = [
    "powershell",
    "invoke-webrequest",
    "downloadstring",
    "cmd.exe",
    "base64",
    "keylogger",
    "ransomware",
    "password stealer"
]

KNOWN_MALICIOUS_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e"
}


def calculate_hash(file_path):

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:

            while True:
                data = file.read(4096)

                if not data:
                    break

                sha256.update(data)

        return sha256.hexdigest()

    except Exception:
        return None


def scan_file(file_path):

    threats = []
    score = 0

    filename = os.path.basename(file_path).lower()
    extension = os.path.splitext(filename)[1]

    # Check extension
    if extension in SUSPICIOUS_EXTENSIONS:
        threats.append("Suspicious file extension")
        score += 30

    # Check filename
    for word in SUSPICIOUS_NAMES:

        if word in filename:
            threats.append("Suspicious filename")
            score += 30
            break

    # Check hash
    file_hash = calculate_hash(file_path)

    if file_hash in KNOWN_MALICIOUS_HASHES:
        threats.append("Known malicious hash")
        score += 100

    # Check file contents
    if extension in {".bat", ".cmd", ".vbs", ".ps1", ".txt"}:

        try:

            with open(
                file_path,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as file:

                content = file.read().lower()

                for pattern in SUSPICIOUS_CONTENT:

                    if pattern in content:

                        threats.append(
                            "Suspicious content: " + pattern
                        )

                        score += 20

        except Exception:
            pass

    if score >= 100:
        status = "MALICIOUS"

    elif score >= 50:
        status = "SUSPICIOUS"

    else:
        status = "SAFE"

    return {
        "file": file_path,
        "status": status,
        "score": score,
        "threats": threats,
        "hash": file_hash
    }


def scan_folder(folder_path):

    results = []

    for root, directories, files in os.walk(folder_path):

        for filename in files:

            file_path = os.path.join(root, filename)

            result = scan_file(file_path)

            results.append(result)

    return results


def quarantine_file(file_path):

    quarantine_folder = os.path.join(
        os.path.dirname(file_path),
        "Quarantine"
    )

    os.makedirs(quarantine_folder, exist_ok=True)

    destination = os.path.join(
        quarantine_folder,
        os.path.basename(file_path)
    )

    shutil.move(file_path, destination)

    return destination