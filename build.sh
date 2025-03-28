#!/bin/bash

rm -rfv build
rm -rfv dist
rm -rfv export_rules.spec

pyinstaller --noconsole --onefile export_rules.py
