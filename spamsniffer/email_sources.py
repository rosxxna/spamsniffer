from __future__ import annotations

import csv
import email
import imaplib
import json
from dataclasses import dataclass
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from pathlib import Path
from typing import Iterable


@dataclass
class EmailItem:
    source_name: str
    subject: str
    body: str
    headers_text: str
    sender: str = ""


def parse_email_file(path: Path) -> list[EmailItem]:
    suffix = path.suffix.lower()
    if suffix in {".txt", ".log"}:
        return [EmailItem(source_name=path.name, subject="", body=path.read_text(encoding="utf-8"), headers_text="")]
    if suffix == ".eml":
        raw = path.read_bytes()
        message = email.message_from_bytes(raw, policy=policy.default)
        return [_email_item_from_message(message, path.name)]
    if suffix == ".csv":
        return _parse_csv(path)
    if suffix == ".json":
        return _parse_json(path)
    raise ValueError(f"Unsupported file format: {suffix}")


def scan_imap_mailbox(
    host: str,
    email_address: str,
    password: str,
    mailbox: str = "INBOX",
    limit: int = 10,
    port: int = 993,
) -> list[EmailItem]:
    items: list[EmailItem] = []
    with imaplib.IMAP4_SSL(host, port) as client:
        client.login(email_address, password)
        client.select(mailbox)
        status, data = client.search(None, "ALL")
        if status != "OK":
            raise RuntimeError("Unable to list mailbox messages.")
        ids = data[0].split()[-limit:]
        for message_id in reversed(ids):
            status, payload = client.fetch(message_id, "(RFC822)")
            if status != "OK":
                continue
            raw_bytes = payload[0][1]
            message = email.message_from_bytes(raw_bytes, policy=policy.default)
            items.append(_email_item_from_message(message, f"{mailbox}:{message_id.decode()}"))
    return items


def _parse_csv(path: Path) -> list[EmailItem]:
    items: list[EmailItem] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader, start=1):
            items.append(
                EmailItem(
                    source_name=f"{path.name} row {index}",
                    subject=row.get("subject", ""),
                    body=row.get("body", row.get("text", "")),
                    headers_text=row.get("headers", ""),
                    sender=row.get("from", row.get("sender", "")),
                )
            )
    return items


def _parse_json(path: Path) -> list[EmailItem]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = [payload]
    items: list[EmailItem] = []
    for index, row in enumerate(payload, start=1):
        items.append(
            EmailItem(
                source_name=f"{path.name} item {index}",
                subject=row.get("subject", ""),
                body=row.get("body", row.get("text", "")),
                headers_text=row.get("headers", ""),
                sender=row.get("from", row.get("sender", "")),
            )
        )
    return items


def _email_item_from_message(message: Message, source_name: str) -> EmailItem:
    subject = _decode_header_value(message.get("Subject", ""))
    sender = _decode_header_value(message.get("From", ""))
    headers_text = "".join(f"{key}: {value}\n" for key, value in message.items())
    body = _extract_message_body(message)
    return EmailItem(
        source_name=source_name,
        subject=subject,
        body=body,
        headers_text=headers_text,
        sender=sender,
    )


def _decode_header_value(value: str) -> str:
    if not value:
        return ""
    return str(make_header(decode_header(value)))


def _extract_message_body(message: Message) -> str:
    if message.is_multipart():
        parts: list[str] = []
        for part in message.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))
            if content_type == "text/plain" and "attachment" not in disposition.lower():
                try:
                    parts.append(part.get_content())
                except Exception:
                    continue
        return "\n".join(parts).strip()
    try:
        return str(message.get_content()).strip()
    except Exception:
        payload = message.get_payload(decode=True) or b""
        return payload.decode(errors="ignore").strip()
