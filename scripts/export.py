#!/usr/bin/env python3
"""Create an encrypted PostgreSQL dump."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlsplit, urlunsplit
from uuid import uuid4


class BackupError(Exception):
    """A diagnostic that is safe to print without subprocess output."""


ENCRYPTION = [
    "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "600000",
    "-md", "sha256", "-salt", "-pass", "env:BACKUP_PASSPHRASE",
]


def dump_connection(value, env):
    """Keep the connection password out of argv and require encrypted remote transport."""
    try:
        uri = urlsplit(value)
        userinfo, separator, authority = uri.netloc.rpartition("@")
        user, password_separator, password = userinfo.partition(":")
        password_supplied = bool(password_separator)
        if (not value or any(ord(char) <= 32 or ord(char) == 127 for char in value)
                or uri.scheme not in ("postgres", "postgresql")
                or not separator or not user or not uri.hostname or "," in uri.hostname
                or len(uri.path) <= 1 or uri.fragment or uri.port == 0):
            raise ValueError
        loopback = uri.hostname in ("localhost", "127.0.0.1", "::1")
        options = []
        for option in uri.query.split("&") if uri.query else []:
            raw_name, equal, raw_value = option.partition("=")
            name = unquote(raw_name, errors="strict")
            if not equal or name in ("sslpassword", "host", "hostaddr", "port", "service"):
                raise ValueError
            if name == "password":
                if password_supplied:
                    raise BackupError("Supply the database password only once in the URI.")
                password_supplied = True
                password = raw_value
                continue
            if name == "sslmode" and not loopback:
                if unquote(raw_value, errors="strict") not in ("require", "verify-ca", "verify-full"):
                    raise BackupError("Remote database connections require TLS.")
            options.append(option)
        password = unquote(password, errors="strict")
        if "\0" in password:
            raise ValueError
    except ValueError:
        raise BackupError("Use an explicit PostgreSQL session connection URI.") from None
    clean_uri = urlunsplit(uri._replace(netloc=f"{user}@{authority}", query="&".join(options)))
    env = {**env, "PGCONNECT_TIMEOUT": "15", "PGSSLMODE": "prefer" if loopback else "require"}
    if password:
        env["PGPASSWORD"] = password
    elif os.environ.get("PGPASSFILE"):
        env["PGPASSFILE"] = os.environ["PGPASSFILE"]
    return clean_uri, env


@contextmanager
def backup_stream(argv, env):
    with subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
    ) as producer:
        try:
            yield producer
        except BaseException:
            # A blocked producer may never observe that its pipe was closed.
            producer.kill()
            producer.wait()
            raise


def archive_listing(encrypted, env, encryption_env):
    with backup_stream([*ENCRYPTION, "-d", "-in", str(encrypted)], encryption_env) as decrypt:
        listing = subprocess.run(
            ["pg_restore", "--list"], stdin=decrypt.stdout,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env,
        )
        if listing.returncode:
            raise BackupError("Encrypted archive could not be read back.")
        # pg_restore can stop at the archive directory. Drain the remaining
        # decrypted bytes so OpenSSL checks the complete encrypted stream.
        with open(os.devnull, "wb") as discard:
            shutil.copyfileobj(decrypt.stdout, discard)
        if decrypt.wait():
            raise BackupError("Encrypted archive could not be read back.")
    return listing.stdout.splitlines()


def create_backup(directory):
    passphrase = os.environ.get("BACKUP_PASSPHRASE")
    if not passphrase:
        raise BackupError("Set BACKUP_PASSPHRASE before running the backup.")
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("PG") and key not in ("DATABASE_URL", "BACKUP_PASSPHRASE")}
    uri, dump_env = dump_connection(os.environ.get("DATABASE_URL", ""), env)
    encryption_env = {**env, "BACKUP_PASSPHRASE": passphrase}
    os.umask(0o077)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")
    filename = f"export-{timestamp}-{uuid4().hex[:8]}.dump.enc"
    with tempfile.TemporaryDirectory(prefix=".export-", dir=directory) as draft:
        encrypted = Path(draft) / filename
        with backup_stream(
            ["pg_dump", "--no-password", "--dbname", uri, "--format=custom", "--no-owner",
             "--schema=public", "--schema=delivery_private", "--extension=citext"],
            dump_env,
        ) as dump:
            encryption = subprocess.run(
                [*ENCRYPTION, "-out", str(encrypted)], stdin=dump.stdout,
                stderr=subprocess.DEVNULL, env=encryption_env,
            )
            dump.stdout.close()
            if encryption.returncode:
                raise BackupError("Database backup encryption failed.")
            if dump.wait():
                raise BackupError("Database dump failed. Check the connection, access and PostgreSQL client version.")
        listing = archive_listing(encrypted, env, encryption_env)
        entries = [line for line in listing if " TABLE DATA " in line]
        if not any(" TABLE DATA " in line for line in entries):
            raise BackupError("Export has no table data.")
        if any(" SCHEMA - delivery_private " in line for line in listing):
            for table in ("provider_bindings", "provider_credentials"):
                if not any(f" TABLE DATA delivery_private {table} " in line for line in entries):
                    raise BackupError("Database backup is missing provider ownership or credential data.")
        result = directory / filename
        os.link(encrypted, result)
    print(f"Tables: {len(entries)}", file=sys.stderr)
    return result


def interrupt(_signum, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupt)
    try:
        print(create_backup(args.output_dir.resolve(strict=True)))
    except BackupError as error:
        print(error, file=sys.stderr)
        return 1
    except OSError:
        print("Backup could not run. Check PostgreSQL tools, OpenSSL and the output directory.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Backup interrupted.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
