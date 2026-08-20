"""Guarantees about the distribution itself, checked against the installed package."""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

import simple_nfc_tag as snt


def test_version_is_pep440():
    assert re.fullmatch(r"\d+\.\d+\.\d+(\.(dev|a|b|rc)\d+)?", snt.__version__)


def test_py_typed_ships_with_the_package():
    marker = pathlib.Path(snt.__file__).with_name("py.typed")
    assert marker.is_file(), "PEP 561 marker missing; annotations will not reach consumers"


def test_importing_the_package_does_not_touch_pyscard():
    """The hardware-free path must not depend on a working PC/SC stack.

    pyscard loads a compiled extension against libpcsclite. If importing this package
    pulled it in, the suite could not run in CI, which has no reader and no PC/SC
    daemon.
    """
    result = subprocess.run(
        [sys.executable, "-c", "import simple_nfc_tag, sys; print('smartcard' in sys.modules)"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "False"
