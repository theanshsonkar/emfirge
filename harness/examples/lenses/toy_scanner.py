"""A toy scanner, used by the tests as an outside tool. It knows nothing of Emfirge: it reads the account at
AWS_ENDPOINT_URL (an http address answering /state.json, or a file path) and prints one JSON line per failed check."""
import json
import os
import sys
import time
import urllib.request

endpoint = os.environ['AWS_ENDPOINT_URL']
time.sleep(float(os.environ.get('TOY_SLEEP', '0')))
if os.environ.get('TOY_EXIT'):
    sys.exit(int(os.environ['TOY_EXIT']))
if endpoint.startswith('http'):
    state = json.load(urllib.request.urlopen(endpoint + '/state.json', timeout=5))
else:
    state = json.load(open(endpoint))
for bucket in state.get('buckets', []):
    if bucket.get('public'):
        print(json.dumps({'check': 'bucket_public', 'resource': bucket['name'], 'status': 'FAIL', 'message': f"{bucket['name']} is public"}))
    if not bucket.get('encrypted', True):
        print(json.dumps({'check': 'bucket_unencrypted', 'resource': bucket['name'], 'status': 'FAIL', 'message': f"{bucket['name']} is not encrypted"}))
