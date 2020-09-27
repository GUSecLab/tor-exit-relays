#!/usr/bin/env python3
import os
import sys
import re


def print_err():
    print("TBB Data Directory not found.")
    print("Please manually set control_auth_cookie path to config.json")
    print("Otherwise you won't use new circuits toward broker site")


def get_tbb_ctrl_cookie_path_linux(tbb_dir):
    if tbb_dir[0] == "~":
        tbb_dir = os.path.expanduser(tbb_dir)
    a = list(set([val for sublist in [[i[0]] for i in os.walk(tbb_dir)] for val in sublist]))
    tor_dir = ''
    for i in a:
        if "Browser/TorBrowser/Data/Tor" in i:
            tor_dir = i.split("Browser/TorBrowser/Data/Tor")[0] + "Browser/TorBrowser/Data/Tor"
            break
    if tor_dir == '':
        print_err()
        return None
    tbb_ctrl_cookie_path = os.path.join(tor_dir, "control_auth_cookie")
    return tbb_ctrl_cookie_path


def check_tbb_ctrl_cookie_path_mac():
    default_dir = "~/Library/Application Support/TorBrowser-Data/Tor"
    if os.path.exists(os.path.expanduser(default_dir)):
        return os.path.join(os.path.expanduser(default_dir), "control_auth_cookie")
    else:
        print_err()
        return None
