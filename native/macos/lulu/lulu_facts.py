#!/opt/homebrew/bin/python3
"""Read fixed LuLu plists and emit scoped facts. No authorization decision."""
import hashlib
import json
import os
import plistlib
import pwd
import stat
import sys

PREFERENCES = '/Library/Objective-See/LuLu/preferences.plist'
RULES = '/Library/Objective-See/LuLu/rules.plist'
FIELDS = ('key', 'path', 'endpointAddr', 'endpointPort', 'action',
          'isEndpointAddrRegex', 'isDisabled', 'pid', 'expiration')
SUPPLEMENTAL_FIELDS = ('scope', 'type', 'endpointHost')
PREFS = ('disabled', 'allowDNS', 'allowLocalHost', 'useAllowList', 'currentProfile')
CLAUDE = '/Applications/Claude.app'
CLAUDE_ROOT = '/Applications/Claude.app/Contents/'
SUN_SUFFIX = '/Library/Application Support/adspower_global/cwd_global/'


def safe_read(path, strict=True):
    parts = path.split('/')[1:]
    if not path.startswith('/') or not parts or any(not p or p in ('.', '..') for p in parts):
        raise ValueError('invalid path')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            next_fd = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                              (0 if last else os.O_DIRECTORY), dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            if strict and (info.st_uid != 0 or info.st_mode & 0o022):
                raise ValueError('unsafe owner or mode')
            if last and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                         info.st_size < 1 or info.st_size > 16 * 1024 * 1024):
                raise ValueError('unsafe file')
        data = bytearray()
        while len(data) <= 16 * 1024 * 1024:
            block = os.read(fd, 65536)
            if not block:
                return bytes(data)
            data.extend(block)
        raise ValueError('file grew')
    finally:
        os.close(fd)


def decode_archive(data):
    archive = plistlib.loads(data)
    objects = archive['$objects']
    root = archive['$top']['root']
    if not isinstance(objects, list) or len(objects) > 200_000:
        raise ValueError('archive objects')

    def decode(value, depth=0, active=frozenset()):
        if depth > 64:
            raise ValueError('archive depth')
        if isinstance(value, plistlib.UID):
            index = value.data
            if index == 0:
                return None
            if index >= len(objects) or index in active:
                raise ValueError('archive reference')
            return decode(objects[index], depth + 1, active | {index})
        if isinstance(value, list):
            return [decode(x, depth + 1, active) for x in value]
        if isinstance(value, dict):
            if 'NS.keys' in value:
                keys = decode(value['NS.keys'], depth + 1, active)
                vals = decode(value['NS.objects'], depth + 1, active)
                if not isinstance(keys, list) or not isinstance(vals, list) or len(keys) != len(vals):
                    raise ValueError('archive dictionary')
                return dict(zip(keys, vals))
            if 'NS.objects' in value:
                return decode(value['NS.objects'], depth + 1, active)
            return {k: decode(v, depth + 1, active) for k, v in value.items() if k != '$class'}
        return value

    return decode(root)


def atom(value):
    if value is None or isinstance(value, (bool, int, str)):
        return value
    # Matches json.dumps(default=str) in the incumbent digest for plist dates/bytes.
    return str(value)


def collect(preferences_path=PREFERENCES, rules_path=RULES, home=None, strict=True):
    if home is None:
        home = pwd.getpwuid(os.getuid()).pw_dir
    if not home.startswith('/') or home.endswith('/') or '\0' in home or '/..' in home:
        raise ValueError('home path')
    pref_data = safe_read(preferences_path, strict)
    rule_data = safe_read(rules_path, strict)
    prefs = plistlib.loads(pref_data)
    archive = decode_archive(rule_data)
    if not isinstance(prefs, dict) or not isinstance(archive, dict):
        raise ValueError('plist structure')
    roots = (CLAUDE_ROOT, home + SUN_SUFFIX)
    selected = []
    for item in archive.values():
        if not isinstance(item, dict) or not isinstance(item.get('rules', []), list):
            raise ValueError('rules structure')
        for rule in item.get('rules', []):
            if not isinstance(rule, dict):
                raise ValueError('rule structure')
            path = rule.get('path', '')
            if not isinstance(path, str):
                raise ValueError('rule path')
            if path == CLAUDE or path.startswith(roots):
                selected.append({key: atom(rule.get(key)) for key in
                                 FIELDS + SUPPLEMENTAL_FIELDS})
                if len(selected) > 4096:
                    raise ValueError('too many scoped rules')
    return {'schemaVersion': 1, 'home': home,
            'preferencesFileSHA256': hashlib.sha256(pref_data).hexdigest(),
            'rulesFileSHA256': hashlib.sha256(rule_data).hexdigest(),
            'preferences': {key: atom(prefs.get(key)) for key in PREFS},
            'rules': selected}


def main():
    if len(sys.argv) != 1:
        raise ValueError('fixed-path helper accepts no arguments')
    facts = collect()
    print(json.dumps(facts, sort_keys=True, separators=(',', ':'), ensure_ascii=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, plistlib.InvalidFileException):
        print('LuLu facts unavailable', file=sys.stderr)
        raise SystemExit(1)
