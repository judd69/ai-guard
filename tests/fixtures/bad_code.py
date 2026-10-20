"""Deliberately bad AI-generated-style code — every check should fire here."""
import os
import fastjson  # hallucinated: not a real package

import pickle
import requests

API_KEY = "sk-abcdefghijklmnopqrstuvwx1234567890ABCD"  # leaked secret
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # dummy value ending in EXAMPLE -> skipped by design
REAL_AWS = "AKIAZZZZZZZZZZZZZZZZ"  # leaked secret


def run_query(user_input):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    return eval(query)  # dangerous: non-literal eval


def load_data(blob):
    return pickle.loads(blob)  # dangerous: pickle deserialization


def fetch(url):
    return requests.get(url)  # network: missing timeout


def fetch_insecure(url):
    return requests.get(url, verify=False, timeout=5)  # network: verify=False


def risky(cmd):
    os.system(cmd)  # dangerous: shell


def sloppy():
    try:
        risky("ls")
    except:  # weak: bare except
        pass


def sloppier(urls):
    for url in urls:
        try:
            fetch(url)
        except Exception:  # weak: swallowed exception
            continue


# TODO: rest of the code goes here, implement this later  (ai-tell comment)

x = "this is a very long line that goes on and on and on and on and on and on and on and on and on and on and on and on and on and on and on and on and on and on!!!"  # noqa
