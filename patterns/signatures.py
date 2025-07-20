"""
File Signature Database for Evyl Framework

Contains file signatures for identifying file types and potential security issues.
"""

# Magic bytes for file type identification
FILE_SIGNATURES = {
    # Archives
    'zip': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
    'rar': [b'Rar!\x1a\x07\x00', b'Rar!\x1a\x07\x01\x00'],
    'tar': [b'ustar\x00', b'ustar  \x00'],
    'gzip': [b'\x1f\x8b'],
    '7z': [b'7z\xbc\xaf\x27\x1c'],
    
    # Images
    'jpeg': [b'\xff\xd8\xff'],
    'png': [b'\x89PNG\r\n\x1a\n'],
    'gif': [b'GIF87a', b'GIF89a'],
    'bmp': [b'BM'],
    'tiff': [b'II*\x00', b'MM\x00*'],
    
    # Documents
    'pdf': [b'%PDF-'],
    'doc': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
    'docx': [b'PK\x03\x04\x14\x00\x06\x00'],
    'xls': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
    'xlsx': [b'PK\x03\x04\x14\x00\x06\x00'],
    'ppt': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
    'pptx': [b'PK\x03\x04\x14\x00\x06\x00'],
    
    # Executables
    'exe': [b'MZ'],
    'elf': [b'\x7fELF'],
    'dmg': [b'x\x01\x73\x0d\x62\x62\x60'],
    'deb': [b'!<arch>\ndebian'],
    'rpm': [b'\xed\xab\xee\xdb'],
    
    # Scripts
    'sh': [b'#!/bin/sh', b'#!/bin/bash'],
    'py': [b'#!/usr/bin/python', b'#!/usr/bin/env python'],
    'pl': [b'#!/usr/bin/perl', b'#!/usr/bin/env perl'],
    'rb': [b'#!/usr/bin/ruby', b'#!/usr/bin/env ruby'],
    
    # Certificates and Keys
    'x509': [b'-----BEGIN CERTIFICATE-----'],
    'rsa_private': [b'-----BEGIN RSA PRIVATE KEY-----'],
    'private_key': [b'-----BEGIN PRIVATE KEY-----'],
    'public_key': [b'-----BEGIN PUBLIC KEY-----'],
    'ssh_rsa': [b'ssh-rsa '],
    'ssh_dsa': [b'ssh-dss '],
    'ssh_ed25519': [b'ssh-ed25519 '],
    
    # Database
    'sqlite': [b'SQLite format 3\x00'],
    'mysql_dump': [b'-- MySQL dump'],
    'postgres_dump': [b'--\n-- PostgreSQL database dump'],
    
    # Config files (by content pattern)
    'json': [b'{\n', b'{"', b'[\n', b'["'],
    'xml': [b'<?xml version=', b'<'],
    'yaml': [b'---\n', b'%YAML'],
    'ini': [b'['],
    
    # Source code
    'java': [b'package ', b'import java.', b'public class '],
    'c': [b'#include <'],
    'cpp': [b'#include <iostream>', b'using namespace std'],
    'php': [b'<?php'],
    'js': [b'function ', b'var ', b'const ', b'let '],
    'html': [b'<!DOCTYPE html>', b'<html>', b'<HTML>'],
    'css': [b'@import', b'@media', b'body {'],
}

# Dangerous file extensions that might contain secrets
DANGEROUS_EXTENSIONS = [
    '.key', '.pem', '.crt', '.cer', '.p12', '.pfx',
    '.env', '.config', '.conf', '.ini', '.properties',
    '.sql', '.db', '.sqlite', '.mdb',
    '.log', '.bak', '.backup', '.old', '.orig',
    '.dump', '.dmp', '.tar.gz', '.zip', '.rar',
    '.json', '.xml', '.yaml', '.yml',
    '.sh', '.bat', '.ps1', '.cmd'
]

# Sensitive file patterns
SENSITIVE_PATTERNS = [
    r'.*\.env.*',
    r'.*config.*',
    r'.*secret.*',
    r'.*password.*',
    r'.*credential.*',
    r'.*key.*',
    r'.*token.*',
    r'.*private.*',
    r'.*backup.*',
    r'.*dump.*',
    r'.*\.sql$',
    r'.*\.db$',
    r'.*\.sqlite$',
    r'.*\.log$',
    r'.*\.bak$',
    r'.*\.old$',
    r'.*id_rsa.*',
    r'.*id_dsa.*',
    r'.*id_ecdsa.*',
    r'.*id_ed25519.*',
]

SIGNATURES = {
    'file_signatures': FILE_SIGNATURES,
    'dangerous_extensions': DANGEROUS_EXTENSIONS,
    'sensitive_patterns': SENSITIVE_PATTERNS
}

def identify_file_type(content: bytes) -> str:
    """Identify file type based on magic bytes"""
    for file_type, signatures in FILE_SIGNATURES.items():
        for signature in signatures:
            if content.startswith(signature):
                return file_type
    return 'unknown'

def is_sensitive_file(filename: str) -> bool:
    """Check if filename matches sensitive patterns"""
    import re
    filename_lower = filename.lower()
    
    for pattern in SENSITIVE_PATTERNS:
        if re.match(pattern, filename_lower):
            return True
    
    return False

def has_dangerous_extension(filename: str) -> bool:
    """Check if file has potentially dangerous extension"""
    filename_lower = filename.lower()
    return any(filename_lower.endswith(ext) for ext in DANGEROUS_EXTENSIONS)