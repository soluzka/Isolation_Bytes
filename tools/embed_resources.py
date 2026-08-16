"""Embed login.html and .env into the C# launcher with heavy obfuscation.

Pipeline: gzip -> PKCS7 padding -> byte permutation (scramble) ->
AES-256-CBC -> double XOR -> C# byte arrays.

The AES key is split into two halves (_keyA and _keyB) so the real key
never appears as a single array in the compiled binary.
"""
import gzip
import hashlib
import json
import os
import random
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


BASE_DIR = Path(__file__).resolve().parent.parent


def _b2c(arr):
    return '{' + ', '.join(str(x) for x in arr) + '}'


def _b2i(arr):
    return '{' + ', '.join(str(x) for x in arr) + '}'


def _encrypt_one(name, plain_path, out_path):
    with open(plain_path, 'rb') as f:
        plain = f.read()

    compressed = gzip.compress(plain, compresslevel=9)
    original_len = len(compressed)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(compressed) + padder.finalize()
    n = len(padded)

    perm = list(range(n))
    random.shuffle(perm)

    aes_key = os.urandom(32)
    aes_iv = os.urandom(16)
    xor1 = os.urandom(32)
    xor2 = os.urandom(32)

    # Derive the real AES key from a 64-byte preimage so the AES key itself
    # never appears directly in the compiled binary.
    preimage = os.urandom(64)
    aes_key = hashlib.sha256(preimage).digest()
    p1 = bytearray(64)
    p2 = bytearray(64)
    for i in range(64):
        p1[i] = os.urandom(1)[0]
        p2[i] = p1[i] ^ preimage[i]

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv))
    enc = cipher.encryptor()
    aes_data = enc.update(bytes(padded)) + enc.finalize()

    scrambled = bytearray(n)
    for i, p in enumerate(perm):
        scrambled[i] = aes_data[p]

    obf = bytearray(len(scrambled))
    for i, b in enumerate(scrambled):
        obf[i] = b ^ xor1[i % len(xor1)] ^ xor2[i % len(xor2)]

    # Decoy arrays that are not used, to hide the real ones.
    decoy1 = [random.randint(0, 255) for _ in range(64)]
    decoy2 = [random.randint(0, 255) for _ in range(48)]

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('namespace AntivirusServerLogin;\n')
        f.write('using System;\n')
        f.write('using System.IO;\n')
        f.write('using System.IO.Compression;\n')
        f.write('using System.Security.Cryptography;\n')
        f.write('using System.Text;\n')
        f.write(f'public static class {name} {{\n')
        f.write('    private static readonly byte[] _p1 = ' + _b2c(p1) + ';\n')
        f.write('    private static readonly byte[] _p2 = ' + _b2c(p2) + ';\n')
        f.write('    private static readonly byte[] _iv = ' + _b2c(aes_iv) + ';\n')
        f.write('    private static readonly byte[] _xor1 = ' + _b2c(xor1) + ';\n')
        f.write('    private static readonly byte[] _xor2 = ' + _b2c(xor2) + ';\n')
        f.write('    private static readonly int[] _perm = ' + _b2i(perm) + ';\n')
        f.write('    private static readonly byte[] _data = ' + _b2c(obf) + ';\n')
        f.write('    private static readonly byte[] _d1 = ' + _b2c(decoy1) + ';\n')
        f.write('    private static readonly byte[] _d2 = ' + _b2c(decoy2) + ';\n')
        f.write('    public static string GetDecrypted() {\n')
        f.write('        byte[] pre = new byte[_p1.Length];\n')
        f.write('        for (int i = 0; i < pre.Length; i++) pre[i] = (byte)(_p1[i] ^ _p2[i]);\n')
        f.write('        byte[] key;\n')
        f.write('        using (SHA256 sha = SHA256.Create()) { key = sha.ComputeHash(pre); }\n')
        f.write('        byte[] blob = (byte[])_data.Clone();\n')
        f.write('        for (int i = 0; i < blob.Length; i++) blob[i] ^= _xor1[i % _xor1.Length];\n')
        f.write('        for (int i = 0; i < blob.Length; i++) blob[i] ^= _xor2[i % _xor2.Length];\n')
        f.write('        byte[] step = new byte[_perm.Length];\n')
        f.write('        for (int i = 0; i < _perm.Length; i++) step[_perm[i]] = blob[i];\n')
        f.write('        using Aes aes = Aes.Create();\n')
        f.write('        aes.Key = key;\n')
        f.write('        aes.IV = _iv;\n')
        f.write('        aes.Mode = CipherMode.CBC;\n')
        f.write('        aes.Padding = PaddingMode.PKCS7;\n')
        f.write('        using ICryptoTransform tf = aes.CreateDecryptor();\n')
        f.write('        byte[] compressed = tf.TransformFinalBlock(step, 0, step.Length);\n')
        f.write('        using MemoryStream ms = new MemoryStream(compressed);\n')
        f.write('        using GZipStream gz = new GZipStream(ms, CompressionMode.Decompress);\n')
        f.write('        using StreamReader rd = new StreamReader(gz, Encoding.UTF8);\n')
        f.write('        return rd.ReadToEnd();\n')
        f.write('    }\n}\n')


def main():
    login_html = BASE_DIR / 'website' / 'login.html'
    dotenv = BASE_DIR / '.env'
    out_dir = BASE_DIR / 'native' / 'AntivirusServerLogin'

    _encrypt_one('LoginHtml', login_html, out_dir / 'LoginHtml.g.cs')
    _encrypt_one('EnvData', dotenv, out_dir / 'EnvData.g.cs')
    print('Resources embedded with heavy obfuscation.')


if __name__ == '__main__':
    main()
