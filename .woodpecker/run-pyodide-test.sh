#!/bin/sh
# SPDX-FileCopyrightText: Christian Amsüss
# SPDX-License-Identifier: MIT

set -xeo pipefail

mkdir -p dist
[ -e dist/pyodide ] || curl -L https://github.com/pyodide/pyodide/releases/download/0.27.2/pyodide-0.27.2.tar.bz2 | bunzip2 | (cd dist && tar x)

if [ -z "${CI}" ]
then
    python3 -m venv .pyodide-venv
    . ./.pyodide-venv/bin/activate
fi

# We need to have the right wheels in dist/ so that pytest-pyodide can pick
# them up and install them in the browser. (Most of the time this will have
# happened already, but not when debugging CI)
pip install build
python3 -m build

pip install pytest-pyodide

# We need this extra locally so that the suitable transport can be spawned
pip install websockets

python3 -Xdev -m pytest -k pyodide --runtime firefox --dist-dir=./dist/pyodide
