import hashlib
import os
import shutil
import sys
import zipfile

import requests
from dotenv import load_dotenv
from tabulate import tabulate

load_dotenv()

BASE_DIR = os.path.dirname(__file__)
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
MALWARE_BAZAAR_AUTH_KEY = os.getenv("MALWARE_BAZAAR_AUTH_KEY")
CHUNK_SIZE = 64 * 1024
DUMP_PATH = f"{BASE_DIR}/data/full_sha256.txt"
TABLE_COLUMNS = ["malicious", "suspicious", "harmless", "undetected"]


def prepare_database(dump_path):
    if not os.path.exists(dump_path):
        print("Local database not found...Download starts now...")
        update_local_db(dump_path)
        return
    else:
        with open(dump_path) as dump:
            last_update = read_dump_date(dump.read(1000))
            if last_update is None:
                last_update = "unknown"
        print(
            f"Local database updated by MalwareBazaar on: {last_update}\nUpdating more than once per hour is useless, since the full dump is generated hourly."
        )
        while True:
            want_update = (
                input("Do you want to update your local database? yes/no: ")
                .lower()
                .strip()
            )

            match want_update:
                case "yes":
                    update_local_db(dump_path)
                    break
                case "no":
                    break


def read_dump_date(text) -> str | None:
    for line in text.splitlines():
        if line.startswith("# Last updated"):
            return line.partition(":")[2].strip(" #")


def download_dump(destination_path):
    address = f"https://mb-api.abuse.ch/v2/files/exports/{MALWARE_BAZAAR_AUTH_KEY}/sha256_full.txt.zip"
    response = requests.get(address, stream=True, timeout=30)
    if response.status_code != 200:
        raise RuntimeError(f"{response.status_code}")

    with open(destination_path, "wb") as f:
        f.writelines(response.iter_content(chunk_size=CHUNK_SIZE))


def extract_dump(zip_path, destination_path):
    with (
        zipfile.ZipFile(zip_path) as zip_file,
        zip_file.open("full_sha256.txt") as text_file,
        open(destination_path, "wb") as destination_file,
    ):
        shutil.copyfileobj(text_file, destination_file)


def is_valid_dump(text) -> bool:
    return read_dump_date(text) is not None and len(read_hash(text)) > 0


def install_dump(new_path, dump_path):
    with open(new_path) as f:
        text = f.read()
        result = is_valid_dump(text)

    if result:
        os.replace(new_path, dump_path)
    else:
        os.remove(new_path)
        raise ValueError("Dump not valid")


def update_local_db(dump_path):
    folder_name = os.path.dirname(dump_path)
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    zip_path = f"{dump_path}.zip"
    new_path = f"{dump_path}.new"

    try:
        download_dump(zip_path)
        extract_dump(zip_path, new_path)
        install_dump(new_path, dump_path)
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)
        if os.path.exists(new_path):
            os.remove(new_path)


def calculate_hash(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            h.update(chunk)
            if chunk == b"":
                return h.hexdigest()


def read_hash(text) -> set:
    hash_set = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#") or line == "":
            continue
        hash_set.add(line)
    return hash_set


def offline_check(file_hash, hashes_known) -> str:
    if file_hash.strip().lower() in hashes_known:
        return "WARNING: Hash found in local database!"
    return "Hash not found in local database. This does not mean it's safe."


def load_hashes(path) -> set:
    with open(path) as f:
        dump_text = f.read()
    return read_hash(dump_text)


def extract_data_virustotal(response) -> dict:
    if response is None:
        return {}
    response = response.get("data", {})
    response = response.get("attributes", {})
    response = response.get("last_analysis_stats", {})
    return response


def format_data_in_table(data) -> str:
    if data is None or data == {}:
        return ""
    riga = {}
    for column in TABLE_COLUMNS:
        riga[column] = data.get(column, "")
    return tabulate([riga], headers="keys", tablefmt="github", colglobalalign="center")


def query_virustotal(file_hash) -> dict | None:
    address = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    response = requests.get(
        address, headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=10
    )
    match response.status_code:
        case 200:
            return response.json()
        case 404:
            return None
        case 401:
            raise ValueError("Incorrect or missing key")
        case 429:
            raise RuntimeError("Too many requests")
        case _:
            raise RuntimeError(f"{response.status_code}")


def main():
    if len(sys.argv) != 2:
        sys.exit("Please insert a correct path.")
    if not VIRUSTOTAL_API_KEY or not MALWARE_BAZAAR_AUTH_KEY:
        sys.exit(
            "Please insert API keys in your .env file. Read README for further informations."
        )

    try:
        file_hash = calculate_hash(sys.argv[1])
    except FileNotFoundError:
        sys.exit(f"File not found: {sys.argv[1]}")
    except IsADirectoryError:
        sys.exit(f"Directory Error: {sys.argv[1]} - please check path")
    except PermissionError:
        sys.exit(f"Could not load {sys.argv[1]}: PermissionError")

    try:
        prepare_database(DUMP_PATH)
    except (RuntimeError, ValueError, zipfile.BadZipFile, KeyError) as e:
        sys.exit(f"Error: {e}")
    except requests.exceptions.RequestException:
        sys.exit("Could not update the local database. Check your internet connection.")

    try:
        hashes_known = load_hashes(DUMP_PATH)
    except FileNotFoundError:
        sys.exit("Local database not found.")
    print(offline_check(file_hash, hashes_known))

    try:
        query = query_virustotal(file_hash)
    except (RuntimeError, ValueError) as e:
        sys.exit(f"VirusTotal returned an error: {e}")
    except requests.exceptions.RequestException:
        sys.exit("Could not reach the server. Check your connection")
    if query is None:
        print("Hash not found in VirusTotal..this does not mean that is safe.")
    else:
        print("\nVirusTotal's response:")
        print(format_data_in_table(extract_data_virustotal(query)))
        print(
            "If you want to learn more about what the terms used in this table mean, read the README."
        )


if __name__ == "__main__":
    main()
