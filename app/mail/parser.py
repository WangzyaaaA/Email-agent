from __future__ import annotations

import re
from datetime import datetime, timezone
from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

from bs4 import BeautifulSoup

from app.mail.types import ParsedMail


MAX_BODY_CHARS = 100_000


def _header(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value))).strip()
    except Exception:
        return value.strip()


def _message_text(message: Message) -> tuple[str, list[str]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[str] = []

    parts = message.walk() if message.is_multipart() else [message]
    for part in parts:
        if part.is_multipart():
            continue
        disposition = (part.get_content_disposition() or "").lower()
        filename = _header(part.get_filename())
        if disposition == "attachment" or filename:
            if filename:
                attachments.append(filename[:255])
            continue
        content_type = part.get_content_type()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        if not isinstance(content, str):
            continue
        if content_type == "text/plain":
            plain_parts.append(content)
        else:
            html_parts.append(content)

    if plain_parts:
        text = "\n".join(plain_parts)
    else:
        soup = BeautifulSoup("\n".join(html_parts), "html.parser")
        for element in soup(["script", "style", "noscript", "svg"]):
            element.decompose()
        text = soup.get_text("\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    return text[:MAX_BODY_CHARS], attachments


def _auth_status(message: Message, trusted_auth_domains: tuple[str, ...]) -> str:
    values: list[str] = []
    # Receiving providers prepend their result; never accept a later, sender-supplied
    # Authentication-Results header when the first result is absent or untrusted.
    authentication_results = message.get_all("Authentication-Results", [])
    for value in authentication_results[:1]:
        auth_server = value.split(";", 1)[0].strip().lower()
        if any(auth_server == domain or auth_server.endswith(f".{domain}") for domain in trusted_auth_domains):
            values.append(value)
    # QQ/enterprise systems may only add Received-SPF. Trust it only when the
    # topmost receiving hop itself belongs to the configured provider.
    first_received = str((message.get_all("Received", []) or [""])[0]).lower()
    trusted_hop = any(
        re.search(rf"(?<![a-z0-9.-])(?:[a-z0-9-]+\.)*{re.escape(domain)}(?![a-z0-9.-])", first_received)
        for domain in trusted_auth_domains
    )
    if trusted_hop:
        # Received-SPF normally starts with "pass" or "fail", unlike
        # Authentication-Results which uses "spf=pass". Normalize both forms.
        values.extend(f"spf={value}" for value in message.get_all("Received-SPF", [])[:1])
    if not values:
        return "unknown"
    joined = " ".join(values)
    normalized = joined.lower()
    if re.search(r"\b(?:spf|dkim|dmarc)\s*=\s*(?:fail|softfail|temperror|permerror)", normalized):
        return "fail"
    if re.search(r"\b(?:spf|dkim|dmarc)\s*=\s*pass", normalized):
        return "pass"
    return "unknown"


def _message_ids(value: str | None) -> list[str]:
    if not value:
        return []
    return re.findall(r"<[^>]+>", value)


def parse_mail(
    raw: bytes,
    fallback_date: datetime | None = None,
    trusted_auth_domains: tuple[str, ...] = (),
) -> ParsedMail:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    from_pairs = getaddresses([str(message.get("From", ""))])
    from_name, from_address = from_pairs[0] if from_pairs else ("", "")
    to_pairs = getaddresses([str(message.get("To", "")), str(message.get("Cc", ""))])
    to_addresses = [address.lower() for _, address in to_pairs if address]

    try:
        received_at = parsedate_to_datetime(str(message.get("Date"))) if message.get("Date") else None
    except (TypeError, ValueError, OverflowError):
        received_at = None
    # The IMAP server's INTERNALDATE is authoritative for arrival and scheduling.
    received_at = fallback_date or received_at or datetime.now(timezone.utc)
    if received_at.tzinfo is None:
        received_at = received_at.replace(tzinfo=timezone.utc)
    received_at = received_at.astimezone(timezone.utc)

    text, attachments = _message_text(message)
    in_reply_ids = _message_ids(str(message.get("In-Reply-To", "")))
    return ParsedMail(
        message_id=_header(str(message.get("Message-ID"))) or None,
        subject=_header(str(message.get("Subject", ""))),
        from_address=from_address.lower(),
        from_name=_header(from_name),
        to_addresses=to_addresses,
        received_at=received_at,
        text=text,
        auth_status=_auth_status(message, trusted_auth_domains),
        references=_message_ids(str(message.get("References", ""))),
        in_reply_to=in_reply_ids[-1] if in_reply_ids else None,
        attachment_names=attachments,
    )
