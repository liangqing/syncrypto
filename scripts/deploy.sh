#!/bin/bash

cd `dirname $0`/..

rm -f dist/*

python setup.py bdist_wheel --universal && twine upload dist/*