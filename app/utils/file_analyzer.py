"""
Dillu Analyzer
Supports: PDF, EXE/DLL, Office docs, Archives, Scripts, Images, and more
"""

import hashlib
import os
import re
import struct
import zipfile
import tarfile
import mimetypes
from datetime import datetime


# ── File type registry ──────────────────────────────────────────────────────

MAGIC_SIGNATURES = {
    b'\x25\x50\x44\x46': ('PDF', 'pdf', 'application/pdf'),
    b'\x4d\x5a':         ('Windows PE (EXE/DLL)', 'exe', 'application/x-msdownload'),
    b'\x7f\x45\x4c\x46': ('ELF Executable (Linux)', 'elf', 'application/x-elf'),
    b'\xca\xfe\xba\xbe': ('Mach-O Executable (macOS)', 'macho', 'application/x-mach-o'),
    b'\x50\x4b\x03\x04': ('ZIP / Office Open XML / JAR', 'zip', 'application/zip'),
    b'\x50\x4b\x05\x06': ('ZIP (empty)', 'zip', 'application/zip'),
    b'\x1f\x8b':         ('GZIP Archive', 'gz', 'application/gzip'),
    b'\x42\x5a\x68':     ('BZIP2 Archive', 'bz2', 'application/x-bzip2'),
    b'\xfd\x37\x7a\x58\x5a\x00': ('XZ Archive', 'xz', 'application/x-xz'),
    b'\x52\x61\x72\x21': ('RAR Archive', 'rar', 'application/x-rar'),
    b'\x37\x7a\xbc\xaf': ('7-Zip Archive', '7z', 'application/x-7z-compressed'),
    b'\xd0\xcf\x11\xe0': ('MS Office (legacy .doc/.xls/.ppt)', 'ole', 'application/msword'),
    b'\x89\x50\x4e\x47': ('PNG Image', 'png', 'image/png'),
    b'\xff\xd8\xff':     ('JPEG Image', 'jpg', 'image/jpeg'),
    b'\x47\x49\x46\x38': ('GIF Image', 'gif', 'image/gif'),
    b'\x49\x49\x2a\x00': ('TIFF Image (little-endian)', 'tif', 'image/tiff'),
    b'\x4d\x4d\x00\x2a': ('TIFF Image (big-endian)', 'tif', 'image/tiff'),
    b'\x25\x21\x50\x53': ('PostScript', 'ps', 'application/postscript'),
    b'\x23\x21':         ('Script (shebang)', 'sh', 'text/x-script'),
    b'\xef\xbb\xbf':     ('UTF-8 Text (with BOM)', 'txt', 'text/plain'),
}

EXTENSION_MAP = {
    '.pdf':  ('PDF Document', 'pdf'),
    '.exe':  ('Windows Executable', 'exe'),
    '.dll':  ('Windows DLL', 'exe'),
    '.sys':  ('Windows Driver', 'exe'),
    '.elf':  ('Linux ELF Binary', 'elf'),
    '.so':   ('Shared Library', 'elf'),
    '.dmg':  ('macOS Disk Image', 'macho'),
    '.doc':  ('Word Document (legacy)', 'office'),
    '.docx': ('Word Document', 'office'),
    '.xls':  ('Excel Spreadsheet (legacy)', 'office'),
    '.xlsx': ('Excel Spreadsheet', 'office'),
    '.ppt':  ('PowerPoint (legacy)', 'office'),
    '.pptx': ('PowerPoint', 'office'),
    '.zip':  ('ZIP Archive', 'archive'),
    '.rar':  ('RAR Archive', 'archive'),
    '.7z':   ('7-Zip Archive', 'archive'),
    '.tar':  ('TAR Archive', 'archive'),
    '.gz':   ('GZIP Archive', 'archive'),
    '.jar':  ('Java Archive (JAR)', 'archive'),
    '.apk':  ('Android Package (APK)', 'archive'),
    '.py':   ('Python Script', 'script'),
    '.js':   ('JavaScript', 'script'),
    '.vbs':  ('VBScript', 'script'),
    '.ps1':  ('PowerShell Script', 'script'),
    '.bat':  ('Windows Batch Script', 'script'),
    '.cmd':  ('Windows Command Script', 'script'),
    '.sh':   ('Shell Script', 'script'),
    '.php':  ('PHP Script', 'script'),
    '.rb':   ('Ruby Script', 'script'),
    '.pl':   ('Perl Script', 'script'),
    '.png':  ('PNG Image', 'image'),
    '.jpg':  ('JPEG Image', 'image'),
    '.jpeg': ('JPEG Image', 'image'),
    '.gif':  ('GIF Image', 'image'),
    '.svg':  ('SVG Image', 'image'),
    '.html': ('HTML Document', 'web'),
    '.htm':  ('HTML Document', 'web'),
    '.xml':  ('XML Document', 'web'),
    '.json': ('JSON Data', 'data'),
    '.csv':  ('CSV Data', 'data'),
    '.txt':  ('Text File', 'text'),
    '.rtf':  ('Rich Text Format', 'text'),
    '.iso':  ('ISO Disk Image', 'disk'),
    '.img':  ('Disk Image', 'disk'),
    '.lnk':  ('Windows Shortcut', 'lnk'),
    '.url':  ('Internet Shortcut', 'lnk'),
    '.eml':  ('Email Message', 'email'),
    '.msg':  ('Outlook Message', 'email'),
}

# File types that are inherently high-risk
HIGH_RISK_TYPES = {'exe', 'elf', 'macho', 'script', 'lnk', 'email'}
MEDIUM_RISK_TYPES = {'pdf', 'office', 'archive'}


# ── Core helpers ─────────────────────────────────────────────────────────────

def compute_hashes(file_path):
    hashes = {'md5': hashlib.md5(), 'sha1': hashlib.sha1(), 'sha256': hashlib.sha256()}
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            for h in hashes.values():
                h.update(chunk)
    return {k: v.hexdigest() for k, v in hashes.items()}


def human_size(size):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024:
            return f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} TB'


def detect_file_type(file_path, original_filename):
    """Detect file type from magic bytes + extension."""
    ext = os.path.splitext(original_filename)[1].lower()
    type_info = EXTENSION_MAP.get(ext, ('Unknown File', 'unknown'))
    type_name, type_cat = type_info

    # Check magic bytes
    magic_name, magic_cat = None, None
    try:
        with open(file_path, 'rb') as f:
            header = f.read(8)
        for magic, info in MAGIC_SIGNATURES.items():
            if header[:len(magic)] == magic:
                magic_name, magic_cat = info[0], info[1]
                break
    except Exception:
        pass

    # Magic bytes take priority
    if magic_name:
        type_name = magic_name
        type_cat = magic_cat

    # Detect OOXML types (DOCX/XLSX/PPTX are ZIP files)
    if type_cat in ('zip', 'archive') and ext in ('.docx', '.xlsx', '.pptx', '.apk', '.jar'):
        type_cat = 'archive' if ext in ('.apk', '.jar') else 'office'

    return {
        'type_name': type_name,
        'type_category': type_cat,
        'extension': ext,
        'is_text': _is_text_file(file_path),
    }


def _is_text_file(file_path, sample_size=8192):
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(sample_size)
        # Check for null bytes (binary indicator)
        if b'\x00' in chunk:
            return False
        # Try decoding as UTF-8
        chunk.decode('utf-8')
        return True
    except Exception:
        return False


def get_file_info(file_path, original_filename):
    stat = os.stat(file_path)
    hashes = compute_hashes(file_path)
    file_type = detect_file_type(file_path, original_filename)
    return {
        'filename': original_filename,
        'size': stat.st_size,
        'size_human': human_size(stat.st_size),
        'upload_time': datetime.now().isoformat(),
        'hashes': hashes,
        'file_type': file_type,
    }


# ── Type-specific analyzers ───────────────────────────────────────────────────

def analyze_pe(file_path):
    """Analyze Windows PE (EXE/DLL) files."""
    result = {
        'type': 'PE',
        'is_dll': False,
        'is_64bit': False,
        'sections': [],
        'imports_hint': [],
        'suspicious_strings': [],
        'has_overlay': False,
        'packed_indicators': [],
        'risk_level': 'LOW',
    }
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        # PE header offset
        if data[:2] != b'MZ':
            return result
        pe_offset = struct.unpack_from('<I', data, 0x3c)[0]
        if pe_offset + 6 > len(data):
            return result

        sig = data[pe_offset:pe_offset+4]
        if sig != b'PE\x00\x00':
            return result

        machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
        result['is_64bit'] = machine == 0x8664
        result['machine_type'] = 'x64' if result['is_64bit'] else ('ARM' if machine == 0x01c4 else 'x86')

        chars = struct.unpack_from('<H', data, pe_offset + 22)[0]
        result['is_dll'] = bool(chars & 0x2000)
        result['is_system'] = bool(chars & 0x1000)

        # Section names (suspicious ones)
        num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
        opt_hdr_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
        section_offset = pe_offset + 24 + opt_hdr_size

        suspicious_sections = {'.upx0', '.upx1', '.aspack', '.themida', '.vmp0', '.vmp1', '.enigma1', '.enigma2'}
        for i in range(min(num_sections, 24)):
            off = section_offset + i * 40
            if off + 40 > len(data):
                break
            name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
            result['sections'].append(name)
            if name.lower() in suspicious_sections:
                result['packed_indicators'].append(f'Packer section: {name}')

        # Suspicious string patterns
        strings = _extract_strings(data)
        suspicious_patterns = [
            (r'cmd\.exe|powershell|wscript|cscript', 'Shell execution'),
            (r'regsvr32|rundll32', 'DLL/Script execution'),
            (r'CreateRemoteThread|VirtualAllocEx|WriteProcessMemory', 'Process injection API'),
            (r'IsDebuggerPresent|NtQueryInformationProcess|CheckRemoteDebuggerPresent', 'Anti-debug'),
            (r'GetAsyncKeyState|SetWindowsHookEx', 'Keylogger API'),
            (r'InternetOpen|HttpSendRequest|WinHttpOpen', 'Network activity'),
            (r'RegCreateKey|RegSetValue', 'Registry persistence'),
            (r'CryptEncrypt|CryptDecrypt', 'Cryptography'),
            (r'\\Device\\PhysicalMemory|NtWriteVirtualMemory', 'Kernel/memory access'),
            (r'UPX\d|aPLib|MPRESS|PECompact', 'Packer signature'),
        ]
        all_strings = ' '.join(strings[:500])
        for pattern, label in suspicious_patterns:
            if re.search(pattern, all_strings, re.IGNORECASE):
                result['suspicious_strings'].append(label)

        # Packed heuristic: very few readable strings
        result['possibly_packed'] = len(strings) < 15 or bool(result['packed_indicators'])

        if result['suspicious_strings'] or result['packed_indicators']:
            result['risk_level'] = 'HIGH'
        elif result['possibly_packed']:
            result['risk_level'] = 'MEDIUM'

    except Exception as e:
        result['error'] = str(e)
    return result


def analyze_office(file_path, extension):
    """Analyze Office documents for macros and suspicious content."""
    result = {
        'type': 'Office',
        'has_macros': False,
        'macro_names': [],
        'suspicious_patterns': [],
        'embedded_objects': [],
        'external_links': [],
        'risk_level': 'LOW',
    }
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        content = data.decode('latin-1', errors='replace')

        # OLE (legacy .doc/.xls/.ppt) macro check
        if data[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
            result['format'] = 'OLE (legacy)'
            if b'VBA' in data or b'Macros' in data:
                result['has_macros'] = True
            macro_indicators = [b'AutoOpen', b'AutoExec', b'Document_Open', b'Workbook_Open', b'Auto_Open']
            for ind in macro_indicators:
                if ind in data:
                    result['macro_names'].append(ind.decode())

        # OOXML (.docx/.xlsx/.pptx) — ZIP-based
        elif data[:4] == b'PK\x03\x04':
            result['format'] = 'OOXML (modern)'
            try:
                with zipfile.ZipFile(file_path, 'r') as zf:
                    names = zf.namelist()
                    result['xml_parts'] = len(names)
                    for name in names:
                        if 'vbaProject' in name or name.endswith('.bin'):
                            result['has_macros'] = True
                        if 'externalLinks' in name:
                            result['external_links'].append(name)
                        if 'embeddings' in name:
                            result['embedded_objects'].append(name)
                    # Check xl/workbook.xml for external data connections
                    for name in names:
                        if name.endswith('.xml') or name.endswith('.rels'):
                            try:
                                xml = zf.read(name).decode('utf-8', errors='replace')
                                if 'http://' in xml or 'https://' in xml or 'ftp://' in xml:
                                    result['external_links'].append(f'URL in {name}')
                                if 'DDE' in xml or 'DDEAUTO' in xml:
                                    result['suspicious_patterns'].append('DDE (Dynamic Data Exchange) detected')
                            except Exception:
                                pass
            except Exception as e:
                result['zip_error'] = str(e)

        # Suspicious VBA patterns
        vba_patterns = [
            (r'Shell\s*\(|Shell\s+"', 'Shell execution'),
            (r'CreateObject\s*\(', 'CreateObject call'),
            (r'WScript\.Shell|cmd\.exe', 'Command shell'),
            (r'powershell|pwsh', 'PowerShell execution'),
            (r'URLDownloadToFile|XMLHTTP|WinHttpRequest', 'Network download'),
            (r'AutoOpen|AutoClose|Document_Open|Auto_Open', 'Auto-execute macro'),
            (r'Chr\(\d+\)|ChrW\(\d+\)', 'Char obfuscation'),
            (r'Base64|FromBase64', 'Base64 encoding'),
            (r'Environ\(|GetObject\(', 'Environment/object access'),
        ]
        for pattern, label in vba_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                if label not in result['suspicious_patterns']:
                    result['suspicious_patterns'].append(label)

        if result['has_macros'] and result['suspicious_patterns']:
            result['risk_level'] = 'HIGH'
        elif result['has_macros'] or result['suspicious_patterns']:
            result['risk_level'] = 'MEDIUM'
        elif result['external_links']:
            result['risk_level'] = 'LOW'

    except Exception as e:
        result['error'] = str(e)
    return result


def analyze_archive(file_path, extension):
    """Analyze archives for suspicious content."""
    result = {
        'type': 'Archive',
        'file_count': 0,
        'files': [],
        'suspicious_files': [],
        'nested_archives': [],
        'total_size': 0,
        'risk_level': 'LOW',
    }
    dangerous_extensions = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
                             '.jar', '.scr', '.com', '.pif', '.lnk', '.reg', '.hta', '.wsf'}
    try:
        if extension in ('.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk') or zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, 'r') as zf:
                for info in zf.infolist():
                    ext = os.path.splitext(info.filename)[1].lower()
                    entry = {
                        'name': info.filename,
                        'size': info.file_size,
                        'compressed': info.compress_size,
                        'is_suspicious': ext in dangerous_extensions,
                    }
                    result['files'].append(entry)
                    result['total_size'] += info.file_size
                    if ext in dangerous_extensions:
                        result['suspicious_files'].append(info.filename)
                    if ext in ('.zip', '.rar', '.7z', '.gz', '.tar'):
                        result['nested_archives'].append(info.filename)
            result['file_count'] = len(result['files'])

        elif tarfile.is_tarfile(file_path):
            with tarfile.open(file_path, 'r:*') as tf:
                for member in tf.getmembers():
                    ext = os.path.splitext(member.name)[1].lower()
                    entry = {
                        'name': member.name,
                        'size': member.size,
                        'is_suspicious': ext in dangerous_extensions,
                    }
                    result['files'].append(entry)
                    result['total_size'] += member.size
                    if ext in dangerous_extensions:
                        result['suspicious_files'].append(member.name)
            result['file_count'] = len(result['files'])

    except Exception as e:
        result['error'] = str(e)

    # Bomb ratio check
    if result['total_size'] > 0 and os.path.getsize(file_path) > 0:
        ratio = result['total_size'] / os.path.getsize(file_path)
        result['compression_ratio'] = round(ratio, 1)
        if ratio > 100:
            result['suspicious_files'].append(f'⚠ Potential ZIP bomb (ratio {ratio:.0f}x)')

    if result['suspicious_files']:
        result['risk_level'] = 'HIGH'
    elif result['nested_archives']:
        result['risk_level'] = 'MEDIUM'

    return result


def analyze_script(file_path, extension):
    """Analyze scripts (Python, JS, PS1, Batch, Shell, etc.)."""
    result = {
        'type': 'Script',
        'language': _script_language(extension),
        'line_count': 0,
        'suspicious_patterns': [],
        'obfuscation_indicators': [],
        'network_activity': [],
        'file_operations': [],
        'risk_level': 'LOW',
    }
    try:
        with open(file_path, 'rb') as f:
            raw = f.read()
        try:
            content = raw.decode('utf-8')
        except Exception:
            content = raw.decode('latin-1', errors='replace')

        result['line_count'] = content.count('\n') + 1

        patterns = [
            # Execution
            (r'eval\s*\(|exec\s*\(', 'Dynamic code execution (eval/exec)', 'HIGH'),
            (r'subprocess|os\.system|popen|shell=True', 'Shell command execution', 'HIGH'),
            (r'Invoke-Expression|IEX\s*\(', 'PowerShell IEX execution', 'HIGH'),
            (r'cmd\.exe|/bin/sh|/bin/bash', 'Shell invocation', 'HIGH'),
            # Obfuscation
            (r'base64|b64decode|frombase64', 'Base64 encoding', 'MEDIUM'),
            (r'\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){4,}', 'Hex-encoded string', 'MEDIUM'),
            (r'chr\(\d+\)|ord\(', 'Character-code obfuscation', 'MEDIUM'),
            (r'zlib\.decompress|gzip\.decompress|inflate', 'Compressed payload', 'MEDIUM'),
            # Network
            (r'urllib|requests\.|http\.client|wget|curl|Invoke-WebRequest|WebClient', 'Network request', 'MEDIUM'),
            (r'socket\.connect|bind\(|listen\(', 'Raw socket connection', 'HIGH'),
            # Persistence
            (r'HKEY_|reg add|Registry', 'Registry modification', 'HIGH'),
            (r'crontab|schtasks|at\.exe|launchctl', 'Scheduled task / persistence', 'HIGH'),
            (r'startup|autorun|autostart', 'Autostart mechanism', 'MEDIUM'),
            # Privilege
            (r'sudo|runas|elevation|UAC', 'Privilege escalation', 'HIGH'),
            (r'chmod\s+[0-7]*7|777', 'World-writable permissions', 'MEDIUM'),
        ]

        seen = set()
        for pattern, label, severity in patterns:
            if re.search(pattern, content, re.IGNORECASE) and label not in seen:
                seen.add(label)
                result['suspicious_patterns'].append({'label': label, 'severity': severity})

        # Obfuscation heuristics
        avg_line_len = len(content) / max(result['line_count'], 1)
        if avg_line_len > 300:
            result['obfuscation_indicators'].append('Unusually long lines (possible minification/obfuscation)')
        if len(re.findall(r'\\x[0-9a-fA-F]{2}', content)) > 20:
            result['obfuscation_indicators'].append('High density of hex escapes')
        if content.count(';') > result['line_count'] * 3:
            result['obfuscation_indicators'].append('Semicolon-heavy (obfuscated one-liner style)')

        high = sum(1 for p in result['suspicious_patterns'] if p['severity'] == 'HIGH')
        if high > 0 or result['obfuscation_indicators']:
            result['risk_level'] = 'HIGH'
        elif result['suspicious_patterns']:
            result['risk_level'] = 'MEDIUM'

    except Exception as e:
        result['error'] = str(e)
    return result


def analyze_image(file_path, extension):
    """Analyze images for steganography indicators and embedded content."""
    result = {
        'type': 'Image',
        'format': extension.lstrip('.').upper(),
        'file_size': os.path.getsize(file_path),
        'suspicious_indicators': [],
        'has_embedded_text': False,
        'has_trailing_data': False,
        'risk_level': 'LOW',
    }
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        # Check for appended data after image end markers
        if extension in ('.jpg', '.jpeg'):
            eoi = data.rfind(b'\xff\xd9')
            if eoi != -1 and eoi < len(data) - 2:
                result['has_trailing_data'] = True
                result['suspicious_indicators'].append('Data after JPEG end-of-image marker')

        elif extension == '.png':
            iend = data.rfind(b'IEND')
            if iend != -1 and iend + 8 < len(data):
                result['has_trailing_data'] = True
                result['suspicious_indicators'].append('Data after PNG IEND chunk')

        # Search for embedded PE/ELF/scripts
        if b'MZ' in data[100:]:
            result['suspicious_indicators'].append('Windows PE signature found inside image')
        if b'\x7fELF' in data[100:]:
            result['suspicious_indicators'].append('ELF binary signature found inside image')
        if b'<?php' in data or b'<script' in data.lower():
            result['suspicious_indicators'].append('Script code embedded in image')
            result['has_embedded_text'] = True

        # Check for suspiciously large metadata
        exif_size = len(re.findall(rb'\xff\xe[0-9a-f]', data))
        if exif_size > 10:
            result['suspicious_indicators'].append('Excessive EXIF/metadata chunks')

        if result['suspicious_indicators']:
            result['risk_level'] = 'MEDIUM'

    except Exception as e:
        result['error'] = str(e)
    return result


def analyze_generic(file_path):
    """Generic analysis for any file type — strings, entropy, patterns."""
    result = {
        'type': 'Generic',
        'strings_found': [],
        'suspicious_urls': [],
        'suspicious_ips': [],
        'entropy': 0.0,
        'risk_level': 'LOW',
    }
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        # Entropy calculation
        result['entropy'] = _calculate_entropy(data)
        if result['entropy'] > 7.5:
            result['high_entropy'] = True
            result['suspicious_urls'].append('High entropy (>7.5) — possible encryption/packing')

        # Extract printable strings
        strings = _extract_strings(data, min_len=6)
        result['strings_found'] = strings[:50]

        # URLs
        urls = re.findall(r'https?://[^\s\x00-\x1f"\'<>]{4,100}', ' '.join(strings))
        result['suspicious_urls'] = list(set(urls[:20]))

        # IPs
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ' '.join(strings))
        private = re.compile(r'^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.)')
        result['suspicious_ips'] = [ip for ip in set(ips) if not private.match(ip)][:10]

        if result['suspicious_urls'] or result['suspicious_ips']:
            result['risk_level'] = 'MEDIUM'

    except Exception as e:
        result['error'] = str(e)
    return result


# ── PDF-specific (keep from original) ────────────────────────────────────────

def extract_pdf_metadata(file_path):
    metadata = {}
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        content_str = content.decode('latin-1', errors='replace')
        header_match = re.search(rb'%PDF-(\d+\.\d+)', content)
        if header_match:
            metadata['pdf_version'] = header_match.group(1).decode()
        metadata['page_count'] = len(re.findall(rb'/Type\s*/Page\b', content))
        for key, pattern in [
            ('title', rb'/Title\s*\(([^)]*)\)'),
            ('author', rb'/Author\s*\(([^)]*)\)'),
            ('creator', rb'/Creator\s*\(([^)]*)\)'),
            ('producer', rb'/Producer\s*\(([^)]*)\)'),
            ('creation_date', rb'/CreationDate\s*\(([^)]*)\)'),
        ]:
            m = re.search(pattern, content)
            if m:
                metadata[key] = m.group(1).decode('latin-1', errors='replace')
        metadata['encrypted'] = b'/Encrypt' in content
        metadata['object_count'] = len(re.findall(rb'\d+\s+\d+\s+obj', content))
        metadata['stream_count'] = len(re.findall(rb'\bstream\b', content))
    except Exception as e:
        metadata['error'] = str(e)
    return metadata


def detect_javascript(file_path):
    results = {
        'has_javascript': False,
        'suspicious_patterns': [],
        'risk_level': 'LOW',
    }
    suspicious_patterns = {
        'eval()': r'eval\s*\(',
        'unescape()': r'unescape\s*\(',
        'fromCharCode()': r'fromCharCode\s*\(',
        'document.write()': r'document\.write\s*\(',
        'Shellcode patterns': r'%u[0-9a-fA-F]{4}%u[0-9a-fA-F]{4}',
        'Hex encoding': r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){4,}',
        'app.exec()': r'app\.exec\s*\(',
        'this.eval()': r'this\.eval\s*\(',
        'util.printf()': r'util\.printf\s*\(',
        'media.newPlayer()': r'media\.newPlayer\s*\(',
        'Collab.collectEmailInfo()': r'Collab\.collectEmailInfo\s*\(',
    }
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        content_str = content.decode('latin-1', errors='replace')
        if '/JavaScript' in content_str or '/JS' in content_str:
            results['has_javascript'] = True
        for name, pattern in suspicious_patterns.items():
            if re.search(pattern, content_str, re.IGNORECASE):
                results['suspicious_patterns'].append({
                    'pattern': name,
                    'severity': 'HIGH' if any(k in name.lower() for k in ['eval', 'exec', 'shell']) else 'MEDIUM',
                })
        if results['suspicious_patterns']:
            high = sum(1 for p in results['suspicious_patterns'] if p['severity'] == 'HIGH')
            results['risk_level'] = 'HIGH' if high else 'MEDIUM'
        elif results['has_javascript']:
            results['risk_level'] = 'MEDIUM'
    except Exception as e:
        results['error'] = str(e)
    return results


def extract_embedded_files(file_path):
    embedded = {
        'has_embedded': False,
        'files': [],
        'suspicious_types': [],
        'auto_actions': [],
        'stream_count': 0,
        'risk_level': 'LOW',
    }
    dangerous_extensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr', '.com']
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        content_str = content.decode('latin-1', errors='replace')
        if b'/EmbeddedFile' in content or b'/EmbeddedFiles' in content:
            embedded['has_embedded'] = True
        found_files = set()
        for pattern in [r'/F\s*\(([^)]+)\)', r'/UF\s*\(([^)]+)\)']:
            for m in re.findall(pattern, content_str):
                if m and len(m) > 2:
                    found_files.add(m)
        for fname in found_files:
            ext = os.path.splitext(fname)[1].lower()
            is_suspicious = ext in dangerous_extensions
            embedded['files'].append({'name': fname, 'extension': ext, 'suspicious': is_suspicious})
            if is_suspicious:
                embedded['suspicious_types'].append(fname)
        for marker, label in [(b'/OpenAction', 'OpenAction'), (b'/Launch', 'Launch Action'),
                               (b'/AA', 'Additional Actions'), (b'/SubmitForm', 'SubmitForm')]:
            if marker in content:
                embedded['auto_actions'].append(label)
        embedded['stream_count'] = len(re.findall(r'\bstream\b', content_str))
        if embedded['suspicious_types'] or embedded['auto_actions']:
            embedded['risk_level'] = 'HIGH'
        elif embedded['has_embedded']:
            embedded['risk_level'] = 'MEDIUM'
    except Exception as e:
        embedded['error'] = str(e)
    return embedded


# ── YARA scanning ─────────────────────────────────────────────────────────────

def scan_with_yara(file_path, rules_path):
    results = {'scanned': False, 'matches': [], 'rule_count': 0, 'risk_level': 'LOW'}
    try:
        import yara
        rules = yara.compile(rules_path)
        results['scanned'] = True
        matches = rules.match(file_path)
        for match in matches:
            results['matches'].append({
                'rule': match.rule,
                'description': match.meta.get('description', ''),
                'severity': match.meta.get('severity', 'MEDIUM'),
                'category': match.meta.get('category', 'Unknown'),
                'tags': list(match.tags) if match.tags else [],
            })
        results['rule_count'] = len(matches)
    except ImportError:
        results['scanned'] = True
        results['yara_unavailable'] = True
        results['matches'] = _manual_pattern_scan(file_path)
        results['rule_count'] = len(results['matches'])
    except Exception as e:
        results['error'] = str(e)

    if any(m['severity'] == 'HIGH' for m in results['matches']):
        results['risk_level'] = 'HIGH'
    elif results['matches']:
        results['risk_level'] = 'MEDIUM'
    return results


def _manual_pattern_scan(file_path):
    matches = []
    try:
        with open(file_path, 'rb') as f:
            content = f.read()
        content_str = content.decode('latin-1', errors='replace')
        rules = [
            ('Suspicious_Eval', r'eval\s*\(', 'Dynamic code evaluation (eval)', 'HIGH', 'Execution'),
            ('Suspicious_Shell', r'cmd\.exe|/bin/sh', 'Shell command reference', 'HIGH', 'Execution'),
            ('PDF_OpenAction', r'/OpenAction', 'PDF auto-execute on open', 'HIGH', 'AutoExecution'),
            ('PDF_Launch', r'/Launch', 'PDF Launch action', 'HIGH', 'AutoExecution'),
            ('PDF_JavaScript', r'/JavaScript', 'Embedded JavaScript in PDF', 'MEDIUM', 'JavaScript'),
            ('PE_Injection_API', r'VirtualAllocEx|CreateRemoteThread|WriteProcessMemory', 'Process injection API', 'HIGH', 'Injection'),
            ('Obfuscation_B64', r'base64|fromCharCode|Chr\(\d+\)', 'Obfuscation technique', 'MEDIUM', 'Obfuscation'),
            ('Network_Download', r'URLDownloadToFile|wget|curl|Invoke-WebRequest', 'File download', 'HIGH', 'Network'),
            ('Keylogger_API', r'GetAsyncKeyState|SetWindowsHookEx', 'Keylogger API', 'HIGH', 'Spyware'),
            ('Anti_Debug', r'IsDebuggerPresent|NtQueryInformationProcess', 'Anti-debugging', 'MEDIUM', 'Evasion'),
            ('Registry_Persistence', r'HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE|reg add', 'Registry access', 'MEDIUM', 'Persistence'),
            ('Archive_Bomb', r'', '', '', ''),  # placeholder
        ]
        for rule in rules:
            if not rule[1]:
                continue
            try:
                if re.search(rule[1], content_str, re.IGNORECASE):
                    matches.append({
                        'rule': rule[0], 'description': rule[2],
                        'severity': rule[3], 'category': rule[4], 'tags': []
                    })
            except Exception:
                pass
    except Exception:
        pass
    return matches


# ── Risk scoring ──────────────────────────────────────────────────────────────

def calculate_risk_score(yara_results, type_analysis, file_type_cat):
    score = 0

    # Base score from file type
    if file_type_cat in HIGH_RISK_TYPES:
        score += 20
    elif file_type_cat in MEDIUM_RISK_TYPES:
        score += 5

    # YARA matches
    for match in yara_results.get('matches', []):
        score += 15 if match['severity'] == 'HIGH' else (8 if match['severity'] == 'MEDIUM' else 3)
    score = min(score, 55)

    # Type-specific analysis
    if isinstance(type_analysis, dict):
        risk = type_analysis.get('risk_level', 'LOW')
        score += {'HIGH': 25, 'MEDIUM': 12, 'LOW': 0}.get(risk, 0)

        # Additional scoring for specific indicators
        suspicious = (type_analysis.get('suspicious_patterns') or
                      type_analysis.get('suspicious_strings') or
                      type_analysis.get('suspicious_indicators') or [])
        score += min(len(suspicious) * 3, 15)

        if type_analysis.get('possibly_packed'):
            score += 10
        if type_analysis.get('has_macros'):
            score += 10
        if type_analysis.get('obfuscation_indicators'):
            score += min(len(type_analysis['obfuscation_indicators']) * 5, 15)

    score = min(score, 100)

    if score >= 70:
        level, color = 'CRITICAL', '#ff2d55'
    elif score >= 50:
        level, color = 'HIGH', '#ff6b35'
    elif score >= 25:
        level, color = 'MEDIUM', '#ffd60a'
    else:
        level, color = 'LOW', '#30d158'

    return {'score': score, 'level': level, 'color': color}


# ── Utility helpers ───────────────────────────────────────────────────────────

def _extract_strings(data, min_len=4):
    pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
    return [m.decode('ascii', errors='replace') for m in re.findall(pattern, data)]


def _calculate_entropy(data):
    import math
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    length = len(data)
    for f in freq:
        if f > 0:
            p = f / length
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def _script_language(extension):
    langs = {
        '.py': 'Python', '.js': 'JavaScript', '.vbs': 'VBScript',
        '.ps1': 'PowerShell', '.bat': 'Batch', '.cmd': 'Batch',
        '.sh': 'Shell', '.php': 'PHP', '.rb': 'Ruby', '.pl': 'Perl',
    }
    return langs.get(extension, 'Unknown')
