from __future__ import annotations

import socket
import ssl
import base64
import quopri
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from threading import Event

from imapclient import IMAPClient
from imapclient.exceptions import IMAPClientError, LoginError

from app.config import get_settings
from app.mail.types import ConnectionTestResult, FolderInfo, RemoteMessage


MAX_TEXT_PART_BYTES = 256 * 1024
MAX_TEXT_TOTAL_BYTES = 512 * 1024
MAX_HEADER_BYTES = 64 * 1024
# One FETCH command carries at most this many messages. Batching removes the
# per-message round trip, while the chunk keeps the response bounded: a chunk may
# hold at most FETCH_BATCH_SIZE * MAX_TEXT_TOTAL_BYTES of text before decoding.
FETCH_BATCH_SIZE = 25
# Even a four-part chunk must fit in MAX_TEXT_TOTAL_BYTES, so the per-section cap
# is never allowed to collapse to zero for deeply nested messages.
MIN_TEXT_PART_BYTES = 32 * 1024


@dataclass(slots=True)
class TextPart:
    section: str
    content_type: str
    charset: str
    encoding: str


def _text_flag(flag: bytes | str) -> str:
    return flag.decode("ascii", errors="ignore") if isinstance(flag, bytes) else str(flag)


def _text_value(value: bytes | str | int | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return "" if value is None else str(value)


def _contains_atom(value, atom: bytes) -> bool:  # type: ignore[no-untyped-def]
    if isinstance(value, (bytes, str)):
        return _text_value(value).upper() == atom.decode("ascii")
    if isinstance(value, (tuple, list)):
        return any(_contains_atom(item, atom) for item in value)
    return False


def _part_charset(parameters) -> str:  # type: ignore[no-untyped-def]
    if not isinstance(parameters, (tuple, list)):
        return "utf-8"
    items = list(parameters)
    for index in range(0, len(items) - 1, 2):
        if _text_value(items[index]).upper() == "CHARSET":
            return _text_value(items[index + 1]) or "utf-8"
    return "utf-8"


def text_parts_from_structure(structure) -> list[TextPart]:  # type: ignore[no-untyped-def]
    parts: list[TextPart] = []

    def multipart_children(node) -> list:  # type: ignore[no-untyped-def]
        if not isinstance(node, (tuple, list)) or not node:
            return []
        first = node[0]
        if not isinstance(first, (tuple, list)):
            return []
        # IMAPClient 3.1 groups multipart children in the first tuple and keeps
        # subtype/parameters in the remaining fields. Older parsed structures
        # expose child tuples directly at the start of the parent tuple.
        if first and isinstance(first[0], (tuple, list)):
            return [child for child in first if isinstance(child, (tuple, list))]
        children = []
        for child in node:
            if not isinstance(child, (tuple, list)):
                break
            children.append(child)
        return children

    def walk(node, prefix: str) -> None:  # type: ignore[no-untyped-def]
        if not isinstance(node, (tuple, list)) or not node:
            return
        children = multipart_children(node)
        if children:
            for child_index, child in enumerate(children, start=1):
                section = f"{prefix}.{child_index}" if prefix else str(child_index)
                walk(child, section)
            return
        if len(node) < 6:
            return
        media_type = _text_value(node[0]).upper()
        subtype = _text_value(node[1]).upper()
        if media_type != "TEXT" or subtype not in {"PLAIN", "HTML"} or _contains_atom(node[6:], b"ATTACHMENT"):
            return
        parts.append(
            TextPart(
                section=prefix or "1",
                content_type=f"text/{subtype.lower()}",
                charset=_part_charset(node[2]),
                encoding=_text_value(node[5]).lower(),
            )
        )

    walk(structure, "")
    return parts[:4]


def _decode_part(raw: bytes, part: TextPart) -> str:
    if part.encoding == "base64":
        try:
            raw = base64.b64decode(raw, validate=False)
        except Exception:
            pass
    elif part.encoding in {"quoted-printable", "quotedprintable"}:
        raw = quopri.decodestring(raw)
    try:
        return raw.decode(part.charset or "utf-8", errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def _section_ordering(section: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in section.split("."))
    except ValueError:
        return ()


def _section_response(values: dict, section: str) -> bytes | None:
    """Return a fetched section literal, or None when the server omitted it.

    IMAP servers may answer a partial section request with ``BODY[1]`` or
    ``BODY[1]<0>`` depending on implementation, so the marker is matched on the
    section boundary instead of an exact key.
    """
    marker = f"BODY[{section}]".encode()
    for key, value in values.items():
        if not (isinstance(key, bytes) and key.startswith(marker) and isinstance(value, bytes)):
            continue
        rest = key[len(marker) :]
        if rest == b"" or rest.startswith(b"<"):
            return value
    return None


def _safe_message(header_raw: bytes, bodies: list[tuple[TextPart, str]]) -> bytes:
    original = BytesParser(policy=policy.default).parsebytes(header_raw + b"\r\n")
    safe = EmailMessage(policy=policy.default)
    safe_headers = (
        "From",
        "To",
        "Cc",
        "Subject",
        "Date",
        "Message-ID",
        "References",
        "In-Reply-To",
        "Authentication-Results",
        "Received-SPF",
        "Received",
    )
    for name in safe_headers:
        for value in original.get_all(name, []):
            try:
                safe[name] = str(value)
            except ValueError:
                continue
    plain = "\n".join(text for part, text in bodies if part.content_type == "text/plain")
    html_body = "\n".join(text for part, text in bodies if part.content_type == "text/html")
    safe.set_content(plain or "")
    if html_body:
        safe.add_alternative(html_body, subtype="html")
    return safe.as_bytes()


def folder_role(flags: tuple[bytes | str, ...], name: str) -> str:
    normalized = {_text_flag(flag).lower() for flag in flags}
    lower_name = name.lower()
    if "\\sent" in normalized or lower_name in {"sent", "sent mail", "已发送", "已发送邮件"}:
        return "sent"
    if "\\junk" in normalized or "\\spam" in normalized or lower_name in {"junk", "spam", "垃圾邮件"}:
        return "junk"
    if "\\trash" in normalized:
        return "trash"
    if "\\drafts" in normalized:
        return "drafts"
    if "\\archive" in normalized or "\\all" in normalized:
        return "archive"
    if "\\inbox" in normalized or lower_name == "inbox" or name == "收件箱":
        return "inbox"
    return "other"


def classify_connection_error(exc: Exception, provider: str = "custom") -> tuple[str, str]:
    text = str(exc).lower()
    if isinstance(exc, (socket.timeout, TimeoutError)) or "timed out" in text:
        return "network_timeout", "连接超时，请检查 NAS 网络、防火墙和服务器地址"
    if isinstance(exc, socket.gaierror):
        return "dns_error", "无法解析 IMAP 服务器地址"
    if isinstance(exc, ssl.SSLError):
        return "tls_error", "TLS 证书或加密连接验证失败"
    if isinstance(exc, LoginError) or any(term in text for term in ("authentication", "invalid credential", "login failed", "auth failed")):
        if provider == "alibaba":
            return (
                "alibaba_access_denied",
                "阿里邮箱拒绝登录：请依次确认管理员已放行第三方客户端、已开启 IMAP、使用的是三方客户端安全密码，并检查 IP 白名单",
            )
        return "authentication_failed", "认证失败，请确认使用的是邮箱授权码或应用密码，而不是网页登录密码"
    if "too many" in text or "rate" in text:
        return "rate_limited", "服务器限制了连接频率，系统将稍后自动重试"
    if "denied" in text or "blocked" in text or "not allowed" in text:
        return "access_policy_denied", "服务器访问策略拒绝了第三方客户端或当前 NAS IP"
    if "fetch failed" in text or "could not be fetched" in text:
        return "message_fetch_failed", "邮件同步失败：服务器拒绝了受限正文 section 请求，系统将稍后自动重试"
    return "imap_error", f"IMAP 操作失败：{type(exc).__name__}"


class IMAPMailSource:
    """Persistent, strictly read-only IMAP connection owned by one monitor thread."""

    def __init__(self, host: str, port: int, username: str, password: str, provider: str) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.provider = provider
        self.client: IMAPClient | None = None

    def connect(self) -> None:
        context = ssl.create_default_context()
        self.client = IMAPClient(self.host, port=self.port, ssl=True, ssl_context=context, timeout=20)
        self.client.login(self.username, self.password)

    def close(self) -> None:
        if not self.client:
            return
        try:
            self.client.logout()
        except Exception:
            pass
        self.client = None

    def capabilities(self) -> set[str]:
        assert self.client
        return {_text_flag(item).upper() for item in self.client.capabilities()}

    def list_folders(self) -> list[FolderInfo]:
        assert self.client
        result: list[FolderInfo] = []
        for flags, _delimiter, name in self.client.list_folders():
            name = _text_value(name)
            normalized_flags = tuple(_text_flag(flag) for flag in flags)
            result.append(FolderInfo(name=name, role=folder_role(flags, name), flags=normalized_flags))
        return result

    def select_readonly(self, folder: str) -> dict:
        assert self.client
        return self.client.select_folder(folder, readonly=True)

    def fetch_new(
        self,
        folder: FolderInfo,
        uidvalidity: str,
        last_uid: int,
        initialized: bool,
    ) -> tuple[list[RemoteMessage], int, str]:
        assert self.client
        settings = get_settings()
        info = self.select_readonly(folder.name)
        current_uidvalidity = _text_value(info.get(b"UIDVALIDITY") or info.get("UIDVALIDITY") or uidvalidity or "unknown")
        if current_uidvalidity != uidvalidity:
            last_uid = 0
            initialized = False

        if initialized and last_uid > 0:
            uids = sorted(int(uid) for uid in self.client.search(["UID", f"{last_uid + 1}:*"]) if int(uid) > last_uid)
        else:
            since = (datetime.now(timezone.utc) - timedelta(days=settings.initial_sync_days)).date()
            uids = sorted(int(uid) for uid in self.client.search(["SINCE", since]))
            uids = uids[-settings.initial_sync_limit :]
        if not uids:
            return [], last_uid, current_uidvalidity

        fetched = self.client.fetch(
            uids,
            [f"BODY.PEEK[HEADER]<0.{MAX_HEADER_BYTES}>", b"BODYSTRUCTURE", b"INTERNALDATE"],
        )
        # Parse every structure before downloading bodies: the section list of the
        # whole batch is then known, so text can be fetched with one command per
        # chunk instead of one command per section per message.
        metadata: dict[int, tuple[bytes, datetime | None, list[TextPart]]] = {}
        parts_by_uid: dict[int, list[TextPart]] = {}
        for uid in uids:
            values = fetched.pop(uid, None)
            if not values:
                raise IMAPClientError("fetch failed: required message metadata missing")
            header_raw = _section_response(values, "HEADER")
            structure = values.get(b"BODYSTRUCTURE")
            if not isinstance(header_raw, bytes) or structure is None:
                raise IMAPClientError("fetch failed: required header or BODYSTRUCTURE missing")
            parts = text_parts_from_structure(structure)
            parts_by_uid[int(uid)] = parts
            internal_date = values.get(b"INTERNALDATE")
            if isinstance(internal_date, datetime):
                if internal_date.tzinfo is None:
                    internal_date = internal_date.replace(tzinfo=timezone.utc)
                internal_date = internal_date.astimezone(timezone.utc)
            else:
                internal_date = None
            metadata[int(uid)] = (header_raw, internal_date, parts)

        messages: list[RemoteMessage] = []
        highest_complete = last_uid
        for start in range(0, len(uids), FETCH_BATCH_SIZE):
            chunk = uids[start : start + FETCH_BATCH_SIZE]
            with_parts = [int(uid) for uid in chunk if parts_by_uid.get(int(uid))]
            body_values = self._fetch_text_sections(with_parts, parts_by_uid) if with_parts else {}
            for uid in chunk:
                header_raw, internal_date, parts = metadata.pop(int(uid))
                section_values = body_values.get(int(uid), {})
                bodies: list[tuple[TextPart, str]] = []
                total_bytes = 0
                for part in parts:
                    remaining = MAX_TEXT_TOTAL_BYTES - total_bytes
                    if remaining <= 0:
                        break
                    raw_part = _section_response(section_values, part.section)
                    if raw_part is None:
                        # An absent section is a failed fetch, not an empty body.
                        # Abort this batch so initial-sync and UID checkpoints stay intact.
                        raise IMAPClientError("fetch failed: required text section missing")
                    raw_part = raw_part[:remaining]
                    total_bytes += len(raw_part)
                    bodies.append((part, _decode_part(raw_part, part)))
                raw = _safe_message(header_raw, bodies)
                messages.append(
                    RemoteMessage(
                        folder=folder.name,
                        folder_role=folder.role,
                        uidvalidity=current_uidvalidity,
                        uid=int(uid),
                        raw=raw,
                        internal_date=internal_date,
                        historical=not initialized,
                    )
                )
                highest_complete = int(uid)
        return messages, highest_complete, current_uidvalidity

    def _fetch_text_sections(
        self,
        uids: list[int],
        parts_by_uid: dict[int, list[TextPart]],
    ) -> dict[int, dict]:
        """Fetch the text sections of a chunk with one FETCH per batch.

        The per-section byte limit is divided by the largest part count in the
        chunk, so a single message can never download more than
        ``MAX_TEXT_TOTAL_BYTES`` even when it has four text parts.
        """
        assert self.client
        if not uids:
            return {}
        max_parts = max(len(parts_by_uid[uid]) for uid in uids)
        section_cap = min(MAX_TEXT_PART_BYTES, max(MIN_TEXT_PART_BYTES, MAX_TEXT_TOTAL_BYTES // max_parts))
        sections = sorted(
            {part.section for uid in uids for part in parts_by_uid[uid]},
            key=_section_ordering,
        )
        items = [f"BODY.PEEK[{section}]<0.{section_cap}>" for section in sections]
        responses: dict[int, dict] = {}
        for start in range(0, len(uids), FETCH_BATCH_SIZE):
            responses.update(self.client.fetch(uids[start : start + FETCH_BATCH_SIZE], items))
        return responses

    def wait_for_changes(self, stop_event: Event, timeout: int) -> bool:
        assert self.client
        if "IDLE" not in self.capabilities():
            return not stop_event.wait(timeout)
        inbox = next((folder for folder in self.list_folders() if folder.role == "inbox"), None)
        if not inbox:
            return not stop_event.wait(timeout)
        self.select_readonly(inbox.name)
        self.client.idle()
        try:
            responses = self.client.idle_check(timeout=timeout)
            return bool(responses)
        finally:
            self.client.idle_done()


def test_connection(host: str, port: int, username: str, password: str, provider: str) -> ConnectionTestResult:
    source = IMAPMailSource(host, port, username, password, provider)
    try:
        source.connect()
        folders = source.list_folders()
        capabilities = sorted(source.capabilities())
        inbox = next((folder for folder in folders if folder.role == "inbox"), None)
        if not inbox:
            return ConnectionTestResult(False, "inbox_missing", "连接成功，但未发现收件箱", capabilities, folders)
        source.select_readonly(inbox.name)
        return ConnectionTestResult(True, "ok", "只读连接成功", capabilities, folders)
    except (IMAPClientError, OSError, ssl.SSLError) as exc:
        code, message = classify_connection_error(exc, provider)
        return ConnectionTestResult(False, code, message)
    finally:
        source.close()
