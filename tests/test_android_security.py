from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANDROID = ROOT / "android" / "app" / "src" / "main"


def test_android_manifest_has_only_push_permissions_and_no_cleartext_or_direct_boot() -> None:
    manifest = (ANDROID / "AndroidManifest.xml").read_text(encoding="utf-8")
    permissions = {line.strip() for line in manifest.splitlines() if "uses-permission" in line}
    assert len(permissions) == 4
    assert all(value in manifest for value in ["permission.INTERNET", "permission.CAMERA", "permission.POST_NOTIFICATIONS", "permission.RECEIVE_BOOT_COMPLETED"])
    assert all(value not in manifest for value in ["SEND_SMS", "READ_SMS", "READ_CONTACTS", "WRITE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"])
    assert 'android:usesCleartextTraffic="false"' in manifest
    assert 'android:allowBackup="false"' in manifest
    assert manifest.count('android:directBootAware="false"') >= 2
    assert '<service' in manifest and 'android:exported="false"' in manifest
    assert 'android:name="firebase_messaging_installation_id_enabled"' in manifest
    assert 'android:value="true"' in manifest


def test_android_private_data_is_excluded_from_backup_and_local_schema_has_no_plaintext() -> None:
    backup = (ANDROID / "res" / "xml" / "backup_rules.xml").read_text(encoding="utf-8")
    transfer = (ANDROID / "res" / "xml" / "data_extraction_rules.xml").read_text(encoding="utf-8")
    for domain in ("sharedpref", "database", "file", "root"):
        assert f'domain="{domain}"' in backup
        assert f'domain="{domain}"' in transfer
    store = (ANDROID / "java" / "com" / "mailsentinel" / "push" / "MessageStore.kt").read_text(encoding="utf-8")
    schema = store.split("CREATE TABLE messages", 1)[1].split('"""', 1)[0]
    assert "title" not in schema and "body" not in schema and "content_root_key" not in schema and "device_token" not in schema
    assert "envelope TEXT" in schema


def test_android_uses_fcm_keystore_workmanager_and_has_no_mail_control_or_long_lived_transport() -> None:
    sources = "\n".join(path.read_text(encoding="utf-8") for path in (ANDROID / "java").rglob("*.kt"))
    assert "FirebaseMessagingService" in sources
    assert "onRegistered" in sources
    assert "onNewToken" not in sources
    assert "getInstance().token" not in sources
    assert "AndroidKeyStore" in sources
    assert "WorkManager" in sources
    assert all(value not in sources.lower() for value in ["wss://", "ws://", "startforeground(", "imap", "smtp", "delete email", "mark as read"])
