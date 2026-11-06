#!/usr/bin/env python3
"""Render or publish one approved maintenance notice using the existing admin form.
Publishing is a separate post-GO step; requires the operator's existing session.
"""
import argparse
import html.parser
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from cold import private, require, save

ORIGIN = 'https://status.terrascale.tech'


class Csrf(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.value = None

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == 'input' and d.get('name') == 'csrf':
            self.value = d.get('value')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fields(path):
    f = json.loads(private(path).read_text())
    require(set(f) == {'title', 'message', 'scheduledStart', 'scheduledEnd', 'components'}, 'unexpected notice field')
    require(isinstance(f['components'], list) and f['components'], 'explicit affected component IDs required')
    for name in ('scheduledStart', 'scheduledEnd'):
        require(re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', f[name]), 'UTC schedule required')
    require(f['scheduledStart'] < f['scheduledEnd'], 'invalid window')
    return {**f, 'kind': 'maintenance', 'status': 'scheduled', 'impact': 'major'}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['render', 'publish'])
    p.add_argument('--form', required=True)
    p.add_argument('--cookie')
    p.add_argument('--receipt')
    a = p.parse_args()
    form = fields(a.form)
    if a.action == 'render':
        print(json.dumps(form, indent=2))
        return
    require(a.cookie and a.receipt, 'existing session and new receipt required')
    cookie = private(a.cookie).read_text().strip()
    require('\r' not in cookie and '\n' not in cookie, 'invalid cookie')
    opener = urllib.request.build_opener(NoRedirect)
    headers = {'Cookie': cookie, 'Origin': ORIGIN, 'Referer': ORIGIN + '/admin'}
    with opener.open(urllib.request.Request(ORIGIN + '/admin', headers=headers), timeout=10) as r:
        csrf = Csrf(); csrf.feed(r.read(1024 * 1024).decode())
    require(csrf.value, 'existing admin session unavailable')
    data = urllib.parse.urlencode({**form, 'csrf': csrf.value}, doseq=True).encode()
    try:
        opener.open(urllib.request.Request(ORIGIN + '/admin/incidents', data=data,
                    headers={**headers, 'Content-Type': 'application/x-www-form-urlencoded'}), timeout=10)
        raise RuntimeError('expected redirect; reconcile public history before retry')
    except urllib.error.HTTPError as response:
        location = response.headers.get('Location', '')
        require(response.code in (302, 303) and re.fullmatch(r'/admin/incidents/[0-9A-Z]{26}\?done=created', location),
                'publication not confirmed; reconcile public history before retry')
    public = ORIGIN + location.split('?')[0].removeprefix('/admin')
    with urllib.request.urlopen(public, timeout=10) as r:
        body = r.read(1024 * 1024).decode()
    require(__import__('html').escape(form['title']) in body, 'notice not visible publicly; do not republish blindly')
    save(a.receipt, {'url': public, 'title': form['title'], 'scheduledStart': form['scheduledStart'], 'scheduledEnd': form['scheduledEnd']})
    print(public)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(type(error).__name__ + ': notice not confirmed; inspect public history before retry') from None
