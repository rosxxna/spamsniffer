# SPAMSNIFFER

SPAMSNIFFER is a Python desktop app for checking whether an email or message looks like spam or legitimate mail. It uses a lightweight machine-learning style Naive Bayes classifier, raw header inspection, IMAP mailbox scanning, and SQLite logging.

## Features

- Check pasted text and get a verdict like `spam` or `legit` with percentage scores.
- Load different file formats and scan the email content inside them.
- Connect to an email account over IMAP and scan recent mailbox messages.
- Paste raw email headers and inspect common legitimacy signals.
- Store scan history in SQLite for simple logging and review.
- Uses only Python standard library modules.

## Supported Input Formats

SPAMSNIFFER can import:

- `.txt` or `.log` for plain message text
- `.eml` for raw email files
- `.csv` with columns like `from`, `subject`, `body`, `headers`
- `.json` with objects like:

```json
[
  {
    "from": "sender@example.com",
    "subject": "Hello",
    "body": "Message content",
    "headers": "From: sender@example.com"
  }
]
```

## Project Structure

```text
SPAMSNIFFER/
|-- main.py
|-- run_spamsniffer.bat
|-- README.md
|-- .gitignore
|-- requirements.txt
|-- spamsniffer/
|   |-- __init__.py
|   |-- app.py
|   |-- classifier.py
|   |-- email_sources.py
|   |-- header_analyzer.py
|   |-- storage.py
|   |-- utils.py
|   `-- data/
|       `-- training_corpus.json
|-- samples/
|   |-- sample_email.txt
|   |-- sample_headers.txt
|   |-- sample_message.eml
|   |-- sample_message.json
|   `-- sample_messages.csv
`-- spamsniffer.db
```

## How It Works

### 1. Text Check
Paste email text into the GUI and SPAMSNIFFER gives:

- verdict: `spam` or `legit`
- legit probability
- spam probability
- simple explanation of why the decision was made

### 2. File Scan
Choose a file and SPAMSNIFFER will:

- parse the file format
- extract one or more messages
- classify each message
- show results in the GUI

### 3. Mailbox Scan
Enter:

- IMAP host
- email address
- app password
- mailbox name
- how many recent emails to scan

Then SPAMSNIFFER connects and checks recent emails for likely spam. For Gmail, use an app password instead of your normal password.

### 4. Header Review
Paste raw headers and SPAMSNIFFER checks for signals such as:

- SPF fail
- DKIM fail
- DMARC fail
- mismatched `Reply-To` and `From`
- missing `Return-Path`
- missing `Message-ID`

## Requirements

- Windows, macOS, or Linux
- Python 3.10+ recommended
- Tkinter available in your Python installation

This project does not require third-party Python packages.

## Run

From the project folder:

```bash
python main.py
```

If your system uses the Windows launcher:

```bash
py main.py
```

Or on Windows, double-click:

```text
run_spamsniffer.bat
```

## Notes

- The built-in ML model is intentionally lightweight and easy to understand.
- For production-grade spam filtering, you would usually train on a much larger dataset and add more advanced feature engineering.
- IMAP access depends on your email provider settings.
- The SQLite log file is created automatically as `spamsniffer.db`.

## Suggested Next Improvements

- Train on a real email dataset such as Enron or SpamAssassin.
- Add attachment inspection.
- Add sender/domain reputation checks.
- Export reports to CSV or PDF.
- Package the app into a Windows executable with PyInstaller.
