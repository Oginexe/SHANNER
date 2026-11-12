# SHANNER - a portable malware scanner

## What's the purpose
SHANNER is a project built in Python for educational purposes to practice what I learned in CS50P. I just wanted to develop a personal project that wasn't just homework, but something I'll use multiple times in everyday life: just a personal tool I needed.

SHANNER has two main features: local scanning, and online scanning.

Local scanning is done by using MalwareBazaar's malware database (SHA-256 full database in plain text, .txt) provided by using an Auth-Key, which you get by signing up in abuse.ch's [website](https://auth.abuse.ch/?redirect=https://bazaar.abuse.ch/login/). Local scanning requires an internet connection in order to download the database, but after the first time it's downloaded, it can be used completely offline (except if you want to update the database itself) - but VirusTotal's scan will fail (obviously, without internet connection). In this case the local check will be printed and the program will stop, printing an error message. The database is updated by MalwareBazaar hourly, so updating more than once per hour is useless.

Online scanning is done by using VirusTotal's API Key, which you get by signing up on VirusTotal’s website. Both MalwareBazaar's and VirusTotal's keys are **required** (more info below).

SHANNER calculates your file hash and compares it to the local database and then queries VirusTotal's API.
When using local database the program prints whether the file's SHA-256 hash is in the local database. When using online scanning, it prints a table with detailed results of the query.

## Why SHANNER?
Because it can provide quick results and allows you to check locally without connection. I was searching for a tool that could provide me a fast and simple check without complications.

## How can MalwareBazaar's and VirusTotal's keys be obtained?
It's not so difficult.

- For MalwareBazaar you can simply go to abuse.ch website and sign up: https://auth.abuse.ch/?redirect=https://bazaar.abuse.ch/login/ - you can do it also with using a sign-in link by email. Once you have signed up, you can generate an Auth-Key in your profile.
- For VirusTotal it's the same: https://www.virustotal.com/gui/join-us - once you have signed up, click your user name and open the API key item to see your API key.

Make sure to put both keys in your `.env` file, as in `.env.example`.
## How to use it
SHANNER requires Python 3.10 or newer.

You have to:

- `python3 -m venv .venv`
- `source .venv/bin/activate`
- `pip install -r requirements.txt`
- `cp .env.example .env` and insert both keys
- `python project.py <file>` - you can launch it in the project's folder. The file to scan can be wherever (its path is enough).

Those commands are runnable on Linux and macOS.

The first time you'll run it, it downloads full database automatically (about 42 MiB zipped, 74 MiB unpacked, with more than a million hashes). At every subsequent run, it asks whether you want to update your local database, showing the date of MalwareBazaar’s last database generation.

## How to read VirusTotal's table
Every value is a number of antivirus engines.

- `malicious` &rarr; how many engines say that the file is malicious
- `suspicious` &rarr; how many engines say that the file is suspicious, without being sure
- `harmless` &rarr; how many engines say that the file is harmless
- `undetected` &rarr; how many engines found nothing - this doesn't mean that the file is safe. It is possible that the file contains new malware that none of the engines knows yet.

## Privacy
None of the files you check are submitted to anyone. VirusTotal receives only SHA-256's hash. Keys are in `.env`, and are not printed anywhere.
## Project files

- `project.py` contains hash functions, database's functions (read, download, extract, check, ...), VirusTotal's functions, table functions, and main().
- `test_project.py` contains tests for `read_hash`, `read_dump_date`, `offline_check` and `is_valid_dump`.
- `requirements.txt`: list of required libraries to install
- `.env.example`: .env template with empty values
- `.gitignore`: list of excluded files from repository
## Project's choices
- **Chunked hashes**: the file is read in 64 KiB chunks, one piece at a time. Thanks to this, for example, a file that weighs 2 GB will not use 2 GB of RAM. The result is the same.
- **Local database update**: downloads the zipped database in a temporary file, extracts it, checks that it is a valid dump, and only then replaces the old file. During testing, the server sometimes closed the connection in the middle of a download. This prevents a broken database if a download fails.
## Limits
- Not found does not mean **safe**. For example, if the program does not find the hash in the local database, or if VirusTotal reports a high `undetected` count (or `malicious` = 0), this does not guarantee that the file is clean.
- The local database contains only MalwareBazaar's known malware.
- VirusTotal's API has limits: 500 requests per day, 4 per minute. But the program checks one file at a time, so it should rarely be a problem. The public API may only be used for non-commercial purposes: for more, see [VirusTotal's documentation](https://docs.virustotal.com/reference/public-vs-premium-api).
