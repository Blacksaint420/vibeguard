import requests
import yaml


def fetch(url):
    return requests.get(url, verify=False)


def parse(body):
    return yaml.load(body)
