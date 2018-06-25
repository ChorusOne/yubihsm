Python library and tests for the YubiHSM 2.
This library is compatible with both Python 2 and 3.

This libary communicates with the YubiHSM 2 connector daemon, which must already be running.
See test/test_yubihsm.py for usage examples.

# Quick reference commands:

Run tests: `python setup.py test`
Run test group: `python setup.py test -s test.test_yubihsm.class_xxx`
Run test xxx: `python setup.py test -s test.test_yubihsm.class_xxx.test_yyy`

Access to the device requires proper permissions, so either use sudo or setup a udev rule.

Installation from the repository: `python setup.py install`
Installation from the repository using pip: `pip install .`

# Source releases for distribution:

Build a source release: `python setup.py sdist`

Installation from a source .tar.gz using pip: `pip install dist/yubihsm.<version>.tar.gz`
