#!/bin/bash

rm -f dist/*

python setup.py bdist_wheel && twine upload dist/*