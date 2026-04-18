#!/usr/bin/env python3
"""
Run this once to get your Flickr OAuth tokens.
Usage: python3 get_token.py
"""
import hmac, hashlib, base64, time, random, string
import urllib.parse, urllib.request, webbrowser

def percent_encode(s):
    return urllib.parse.quote(str(s), safe='')

def nonce():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def sign(method, url, params, consumer_secret, token_secret=''):
    sorted_params = '&'.join(
        f'{percent_encode(k)}={percent_encode(v)}'
        for k, v in sorted(params.items())
    )
    base = f'{method}&{percent_encode(url)}&{percent_encode(sorted_params)}'
    key  = f'{percent_encode(consumer_secret)}&{percent_encode(token_secret)}'
    sig  = hmac.new(key.encode(), base.encode(), hashlib.sha1)
    return base64.b64encode(sig.digest()).decode()

def get(url, params, api_key, api_secret, token='', token_secret=''):
    params.update({
        'oauth_consumer_key':     api_key,
        'oauth_nonce':            nonce(),
        'oauth_signature_method': 'HMAC-SHA1',
        'oauth_timestamp':        str(int(time.time())),
        'oauth_version':          '1.0',
    })
    if token:
        params['oauth_token'] = token
    params['oauth_signature'] = sign('GET', url, params, api_secret, token_secret)
    req  = urllib.request.urlopen(f'{url}?{urllib.parse.urlencode(params)}')
    return urllib.parse.parse_qs(req.read().decode())

api_key    = input('API Key:    ').strip()
api_secret = input('API Secret: ').strip()

print('\nStep 1: Getting request token...')
r = get('https://www.flickr.com/services/oauth/request_token',
        {'oauth_callback': 'oob'}, api_key, api_secret)
req_token        = r['oauth_token'][0]
req_token_secret = r['oauth_token_secret'][0]

print('Step 2: Opening Flickr in your browser — authorize the app, then copy the 9-digit code.')
webbrowser.open(
    f'https://www.flickr.com/services/oauth/authorize'
    f'?oauth_token={req_token}&perms=read'
)

verifier = input('\nPaste the 9-digit verifier code: ').strip()

print('\nStep 3: Exchanging for access token...')
r = get('https://www.flickr.com/services/oauth/access_token',
        {'oauth_verifier': verifier},
        api_key, api_secret, req_token, req_token_secret)

print('\n' + '='*50)
print('Paste these into the Flickr Viewer settings:')
print('='*50)
print(f'User NSID:          {r["user_nsid"][0]}')
print(f'Username:           {r["username"][0]}')
print(f'OAuth Token:        {r["oauth_token"][0]}')
print(f'OAuth Token Secret: {r["oauth_token_secret"][0]}')
print('='*50)
print('(These tokens do not expire unless you revoke them.)')
