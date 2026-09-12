"""Зібрати перевірений NativeAPI-пакет для Windows/Linux x86/x64 з CI artifacts."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
COMPONENTS = {
    ('Windows', 'i386'): 'TamgaNative.dll',
    ('Windows', 'x86_64'): 'TamgaNative64.dll',
    ('Linux', 'i386'): 'libTamga32.so',
    ('Linux', 'x86_64'): 'libTamga64.so',
}


def verify_architecture(data, operating_system, architecture):
    if operating_system == 'Windows':
        if data[:2] != b'MZ' or len(data) < 64:
            raise ValueError('Expected a PE binary')
        offset = struct.unpack_from('<I', data, 60)[0]
        if data[offset:offset + 4] != b'PE\0\0':
            raise ValueError('Invalid PE header')
        expected = 0x14c if architecture == 'i386' else 0x8664
        if struct.unpack_from('<H', data, offset + 4)[0] != expected:
            raise ValueError('PE architecture mismatch')
    else:
        if data[:4] != b'\x7fELF' or len(data) < 20 or data[5] != 1:
            raise ValueError('Expected a little-endian ELF binary')
        expected_class, expected_machine = (1, 3) if architecture == 'i386' else (2, 62)
        if data[4] != expected_class or struct.unpack_from('<H', data, 18)[0] != expected_machine:
            raise ValueError('ELF architecture mismatch')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--commit', required=True)
    args = parser.parse_args()
    if args.out.exists():
        parser.error('Use a new output directory')
    args.out.mkdir(parents=True)
    for source in sorted(args.artifacts.rglob('*')):
        if not source.is_file():
            continue
        target = args.out / source.name
        if target.exists():
            raise ValueError('Duplicate release artifact name: ' + source.name)
        shutil.copyfile(source, target)
    for name in ['LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md']:
        shutil.copyfile(ROOT / name, args.out / name)
    for triplet in ['x86-linux', 'x64-linux', 'x86-windows-static', 'x64-windows-static']:
        for name in [f'licenses-{triplet}.zip', f'sbom-{triplet}.json', f'link-map-{triplet}.txt']:
            if not (args.out / name).is_file():
                raise ValueError('Missing required release artifact: ' + name)
    expected_hashes = {}
    with tempfile.TemporaryDirectory(prefix='tamga-release-') as temporary:
        staging = Path(temporary)
        windows = {}
        for arch, manifest_arch in [('x86', 'i386'), ('x64', 'x86_64')]:
            with zipfile.ZipFile(args.out / f'tamga-windows-{arch}.zip') as archive:
                data = archive.read('Tamga.dll')
            verify_architecture(data, 'Windows', manifest_arch)
            windows[arch] = staging / f'Tamga-{arch}.dll'
            windows[arch].write_bytes(data)
            expected_hashes[COMPONENTS[('Windows', manifest_arch)]] = hashlib.sha256(data).hexdigest()
            data = (args.out / f'libTamga-linux-{arch}.so').read_bytes()
            verify_architecture(data, 'Linux', manifest_arch)
            expected_hashes[COMPONENTS[('Linux', manifest_arch)]] = hashlib.sha256(data).hexdigest()
        subprocess.run(['pwsh', '-NoProfile', '-File', str(ROOT / 'scripts/pack-addon.ps1'),
                        '-WindowsX86Dll', str(windows['x86']), '-WindowsX64Dll', str(windows['x64']),
                        '-LinuxX86So', str((args.out / 'libTamga-linux-x86.so').resolve()),
                        '-LinuxX64So', str((args.out / 'libTamga-linux-x64.so').resolve()),
                        '-RequireLinux', '-OutArchive', str((args.out / 'Tamga.zip').resolve())], check=True)
    with zipfile.ZipFile(args.out / 'Tamga.zip') as archive:
        if set(archive.namelist()) != set(COMPONENTS.values()) | {'MANIFEST.XML'}:
            raise ValueError('Unexpected NativeAPI archive contents')
        manifest = ET.fromstring(archive.read('MANIFEST.XML'))
        components = manifest.findall('{http://v8.1c.ru/8.2/addin/bundle}component')
        actual = {(c.get('os'), c.get('arch')): c.get('path') for c in components}
        if len(components) != 4 or actual != COMPONENTS or any(c.get('type') != 'native' for c in components):
            raise ValueError('NativeAPI manifest does not declare all four platforms')
        for platform, name in COMPONENTS.items():
            data = archive.read(name)
            verify_architecture(data, *platform)
            if hashlib.sha256(data).hexdigest() != expected_hashes[name]:
                raise ValueError('Packaged component differs from build artifact: ' + name)
    with zipfile.ZipFile(args.out / 'Tamga-licenses.zip', 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(args.out.iterdir()):
            if path.name in {'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md'} or path.name.startswith('licenses-'):
                archive.write(path, path.name)
    (args.out / 'release-manifest.json').write_text(json.dumps({
        'source_commit': args.commit, 'version': json.loads((ROOT / 'vcpkg.json').read_text())['version'],
        'xml_signatures': True, 'pdf_signatures': True, 'component_sha256': expected_hashes,
        'architecture_and_manifest_verified': True,
    }, indent=2) + '\n', encoding='utf-8')
    checksums = []
    for path in sorted(args.out.iterdir()):
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        checksums.append(f'{digest}  {path.name}')
    (args.out / 'SHA256SUMS.txt').write_text('\n'.join(checksums) + '\n', encoding='utf-8')
    print(f'Verified four NativeAPI components; prepared {len(checksums) + 1} release files')


if __name__ == '__main__':
    main()
