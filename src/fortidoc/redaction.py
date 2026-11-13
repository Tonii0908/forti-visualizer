"""Central rules for removing secrets.

Backups contain password hashes, pre-shared keys, private keys and
certificates. The parser replaces such values with ``REDACTED`` while it
builds the tree, so no later stage (JSON, Excel, HTML, logs, error messages)
can ever see them. The key itself stays visible, so the documentation still
shows *that* a secret is configured.

The rules are deliberately broad: redacting a harmless value is acceptable,
leaking a secret is not.
"""

from __future__ import annotations

from collections.abc import Sequence
from functools import lru_cache

REDACTED = "***entfernt***"

# ASSUMPTION(S1): key name rules. See ANNAHMEN.md.
# Substrings that mark a key as secret wherever they appear in the key name.
_SECRET_SUBSTRINGS = (
    "password",
    "passwd",
    "passphrase",
    "psk",
    "secret",
    "private-key",
    "privkey",
    "keytab",
    "pwd",
)

# Hyphen-separated key components that mark a key as secret.
# A component equal to "key"/"keys" or ending in "key"/"keys" (e.g. "authkey",
# "md5-keys", "key-string") is secret; "keylife" or "keyword" are not.
_KEY_SUFFIXES = ("key", "keys")

# ASSUMPTION(S3): secrets identified by their position, not their key name.
# Path = the config path without the VDOM wrapper ('config global' /
# 'config vdom'), e.g. ('system', 'snmp', 'community'); must match exactly.
_SECRET_PATH_KEYS: dict[tuple[str, ...], frozenset[str]] = {
    # The SNMP community string is stored in clear text as the entry's name.
    ("system", "snmp", "community"): frozenset({"name"}),
}

# A value that contains a PEM/certificate block is always removed.
_PEM_MARKER = "-----BEGIN"


@lru_cache(maxsize=4096)
def is_secret_key(key: str) -> bool:
    """Return True if values of this key must never be shown."""
    lowered = key.lower()
    if any(s in lowered for s in _SECRET_SUBSTRINGS):
        return True
    return any(part.endswith(_KEY_SUFFIXES) for part in lowered.split("-"))


def is_secret_value(values: Sequence[str]) -> bool:
    """Return True if the values themselves reveal a secret, whatever the key."""
    if not values:
        return False
    first = values[0]
    # FortiOS stores encrypted secrets as: set <key> ENC <ciphertext>
    if first == "ENC" or first.startswith("ENC "):
        return True
    return any(_PEM_MARKER in v for v in values)


def is_secret_path_key(path: Sequence[str], key: str) -> bool:
    """Return True if ``key`` is secret at this config path."""
    keys = _SECRET_PATH_KEYS.get(tuple(path))
    return keys is not None and key in keys


def redact_values(
    key: str, values: Sequence[str], path: Sequence[str] = ()
) -> tuple[list[str], bool]:
    """Return (values, redacted). Secret values are replaced by one placeholder."""
    if values and (
        is_secret_key(key) or is_secret_value(values) or is_secret_path_key(path, key)
    ):
        return [REDACTED], True
    return list(values), False


def redact_tokens(words: Sequence[str], path: Sequence[str] = ()) -> list[str]:
    """Redact a raw statement (keyword, key, values...) for error messages.

    Used for lines that may be malformed, so it does not rely on the
    statement being a valid ``set``: everything after a secret-looking key,
    after an ``ENC`` marker or inside a PEM block is removed.
    """
    out: list[str] = []
    for index, word in enumerate(words):
        if word == "ENC" or word.startswith("ENC ") or _PEM_MARKER in word:
            out.append(REDACTED)
            break
        out.append(word)
        if (
            index >= 1
            and (is_secret_key(word) or is_secret_path_key(path, word))
            and index + 1 < len(words)
        ):
            out.append(REDACTED)
            break
    return out
