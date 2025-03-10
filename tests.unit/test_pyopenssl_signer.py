# @file test_pyopenssl_signer.py
# This contains unit tests for the pyopenssl binary wrapper
##
# Copyright (c) Microsoft Corporation
#
# SPDX-License-Identifier: BSD-2-Clause-Patent
##
"""Unit test for the pyopenssl_signer module."""

import unittest
from base64 import b64decode

from edk2toolext.capsule import pyopenssl_signer

r"""
TESTCERT is a cert used to test the ability to parse pfx and pull out necessary information.
To generate a new test cert follow these steps:

1. Generate the Cert (.pfx) file
There are multiple ways to do this, but running this powershell script is the easiest:

``` powershell
$myPwd = ConvertTo-SecureString "password" -Force -AsPlainText
$Cert = New-SelfSignedCertificate `
    -DnsName "www.contoso.com" `
    -CertStoreLocation "Cert:\LocalMachine\My\" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -Subject "CN=Mock Platform Key" `
    -NotAfter (Get-Date).AddYears(10)
Export-PfxCertificate `
    -Cert ("Cert:\LocalMachine\My\"+$Cert.Thumbprint) `
    -FilePath ./Certificate.pfx `
    -Password $myPwd
```

2. Serialize the Cert
Run the following Python commands to read the cert and print the bytes in a
format allowing it to be used in a python file while meeting flake8 requirements:
``` python
from base64 import b64encode
import textwrap
with open("path/to/cert.pfx", 'rb') as file:
    gfg = b64encode(file.read())
    lines = textwrap.wrap(str(gfg), 60, initial_indent="TESTCERT1 = ")
    for t in range(len(lines)):
        end = "\\\n" if t + 1 < len(lines) else "\n"
        print(lines[t], end=end)
```
From there, you can copy the console printed serialized cert and use it in your
python file as seen below this docstring.
"""

# spell-checker:disable
# TESTCERT1 has no password
TESTCERT1 = b"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"

# TESTCERT2 has a password
TESTCERT2 = b"MIIKaQIBAzCCCiUGCSqGSIb3DQEHAaCCChYEggoSMIIKDj\
CCBg8GCSqGSIb3DQEHAaCCBgAEggX8MIIF+DCCBfQGCyqGSIb3DQEMCgECoI\
IE/jCCBPowHAYKKoZIhvcNAQwBAzAOBAh8sw/XNGIGZwICB9AEggTYeUQ8gJ\
GII6HPDeBx4bGH2zkS1ybw4hToh8c9UMd3gwDviCobjkSCidTGZPwkvcfPT8\
3WnZK0Er3fflYL3Y1BD/4Tzzoobstt+Afl7wKiEMWK95xXKe/zFD4ipKN0Z3\
LgpYo+KUvMd5QG0m0OfejLFn/pABkSLFxvHo4KFVHOboqaVZbnG9OftUR2tZ\
dFYaUk/aFSvJKA/M7M/2QI1Byj04bdwFr+1WzEag7kU/Wd/XVmRUTqq9ljmj\
d6xRWuk0NGq4j/OpRIFrJVn585wRlyRl8AGwBf8aIoWgJPK/67y26azde0G5\
YHVDO++sn07K+W2EOaD/UNf21NsD9fZYDyDPTxkKK/e3KjLiKWvK3KG5e7UB\
REKkizsUf7xkP6vRwifyAkC6LgM2UgFhcCYsdsBtMqcWZsjLj5hVg54bBD5Q\
qbcyC5ijUBjBj7ZXKsLDkmZY34VwzzXFcY+jMWhLEojZF9bmO8n58GI4bGhB\
LDL+TzDAiA9cK6VqxGECTW75Z9MkKdECPhfM1L1hTse7M70bo6aX1RwHBHUO\
RkdtEIXIsr1fRf47T83hzlAlxZkDbdtAitnYOUoXI3l+bupIWVpLIcyj+avK\
tdFTIHLmeJR22sy7DTYzS1fYxDlq3MwZmIdRj3LmarM6c4gmk0S/M4f+HvW6\
HyeKt+1cb0E4WlquvLKnRshwdvZ5xV8NL8waOsp4e0xQGPiusDnTspf5ozlc\
eTb3vdE6as0JyYb+YajYZY+3x5Bj4hA3GnQOKRvSQ9h5H7vH5HRQv6NIZrtt\
b9cl6y3R7hMo5uSW5vkWUkus0T6Q47c3SGTtSdqbR5p1+CphQNX6q3bEeQ+r\
fs14CLVtLVFcYoi4+/z33lvkaaZQWvFRHsvKtJIfKcaSJAkBrKXNAJ7nOqbJ\
vXajIcUzmmExTz+73LFj1tHil2RU7YGPqj+Mm0C+/N2xt6u5kD1OPMcdqOGj\
uJNFBdQPOxE3Okdo5zKhIXb12p7P2S3SP3FMZJWS3mEISmGU+4ugctDNINsZ\
YDr9BjPCC6XfRVLZ1VfzTVc9BmcxptcXdfw8U0SHaJ7tBvJfA94k5uo7QNGV\
XC6BLgNAOsimqtFGdtK4mO/wazA28Q/h2bj/KjyFRkXWg52qBSisqA07duwt\
csNOW5MOPWhYGF5ErBBJi1etsHyzqg0UyAN+4I+P8vqc5vnFFbesGOdmMmnU\
18m50yx3bxHU4E3oJF0kiVoAVnjfpDk6uCOf/raWE8W6Aby0jL4tQayX78UE\
G+wPFTBNr0zkX4AfQKvPLVn8PiDiKQ+w7+Mix6kQr3QlcxLVmcOmHKZdr7X/\
XwJlU/q/JNLeheucnd7uaFTHZqXN7Y2m7OlKGC6unCHryV35wjDZnhh1Ug0a\
E8lAejJ2F4vk9oYjHVv1NnwGZ5ZGnaTdasJkbB0LvsG5aQ6qXZ/SpuwK23Ph\
uAFmeW2HrP6UtzJhBAdRWsEYvEl4l9YuD9sC/C+pklAgo1lQB6omPETYE3EW\
VobsvxgJ60CmvLIPXDJMQt4FjrsdzfqnCxuN3F3NT5qnP6tD2Ru1RYcf+TNY\
cM95LW3BhG+FtoPKxU/ABFXCoN+tm0CS+JzB+5TafRbZtkO5iYwk4LXTaHJn\
8p6LF/sCEd1ny6veUJ5HswwzxbUDGB4jANBgkrBgEEAYI3EQIxADATBgkqhk\
iG9w0BCRUxBgQEAQAAADBdBgkqhkiG9w0BCRQxUB5OAHQAZQAtADQANwAzAD\
MAMABiADUAYQAtADEAMABlADUALQA0ADkAMgA4AC0AOQA5AGIANgAtADMAYw\
BkADgAMwBlADQAOAA2AGEAZgA1MF0GCSsGAQQBgjcRATFQHk4ATQBpAGMAcg\
BvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAH\
IAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIwggP3BgkqhkiG9w0BBwagggPoMI\
ID5AIBADCCA90GCSqGSIb3DQEHATAcBgoqhkiG9w0BDAEDMA4ECBULm0ouXg\
M1AgIH0ICCA7B/6IFJ1ecfFG7vxVu7rvmhMDur1+rUvanKPr89jZiDkWHUKp\
KYe0hr0y4y2Yqeiu96krgADjh7fkD/+DwFrXae2ClUEfc3iCq9lfQR4aY/2O\
iY2f6mjiPUxrjj61eeOBr1uHKZ7qoqiwn+1Y724DP4VrFxrg+sshTHzBC7zG\
rNR+RPjpfN0CNYVN5yaZBArGkY4AB1knv3KeYNLVXfDadLsRLhihzmK3l0RY\
GoPi8Lw5MfAQ8Rud7+X/tAH6Hj4Gag9oFCx0rbJ/cVdttSJdVOw0QyUlAi9p\
pl/fcLkKyWMerPHP+SNv+Wndx4lfkxicfIwk99oGUIg0O2I9RA8yPgz17LTt\
2vMAlZAoR0yVTOruJ1BYqv+m3bLJfkuUrtT5mzfYRXuKq6W/w680l+an7D5X\
ekTMEaxiQyO12ExsV/Y3ibEk+kdb0zexvOCVI5yXirsYurSvlP/pAxNdsgD5\
4/a8S94t9pErWcjbAgMTHwOhW/DVyVz1nFJ7ivR8vVNafFqSaYG44kMMffsv\
4DCqVlM4KmDUrcOrvzSY9EDhIWZsCemQ5DfWHznn5niVwv0TXY1nX5KhxgYo\
nz1KNE11pvYYAxXp5i/6ru27unIdHmpmG3yZCZUO/PWKq/Tu5tyQf6LlZ/gn\
/BnK5Nr68wGlN7dJgygmHHsISAB8xDMQq0TnOaYhakK/ozU2fCp78CZT2YSB\
XwDnDxmKMybrztFHo1NNOqFLecV/DilevRnhP9oT9Vcmkl1JhyYcS5XtsTAY\
b25ONknC0g7/h1kav1t068AdphjQPj31M5+Ro1UCyYk06oshC+Y0MGZTIB99\
7LMtqfz+oVXTVdcjNQfgAK77eGKlNpPvWqa5qKWnbBt89TL2g/rXoFT+anQr\
SpfCoxw4K8ykOUx4yW08kpPPg/FePN6zJhs7Eu1W8iLV/gsKBnJmnsLk6aNh\
pv+L5RcHv9AcXN3sbbU2JJE9w5PGuIhoCpyQNjzv+wjMW/jbw4fve63J2Gkc\
J3SYoy1C82t5ZORr8P+6q8jpJqDPjwD2LeTmvNKy8UrYThWkRbaUCetuwMlF\
b1XMtzJcLPOs1/stapsf2C70KgvJ+zgGxob7xvpGLyHecn8ZlVer7jNkzbxD\
xUOq2KAMBksmMAg0Tyc44jDOHiinR7sARTUcNncqP5qJ3d7v7DsCCQsiFD1x\
NEyQpgrD5WAhSaKiZxDvvkj/GNNVXpdiFr8RGa/IlD0+JdiZ3ujt45OduOhs\
ySr03eOImlzjA7MB8wBwYFKw4DAhoEFKn9FVak9/MKt1kvn+GIpIdTy/+pBB\
R7oStX6AVc66qjoj9/dgAPJTqLBwICB9A="
# spell-checker:enable


class Test_pyopenssl_signer(unittest.TestCase):
    """Unit test for the pyopenssl_signer module."""

    def test_empty(self) -> None:
        """Test that the sign function raises an error with bad options."""
        with self.assertRaises((KeyError, ValueError)):
            pyopenssl_signer.sign(None, {}, {})

    def test_proper_options_good_key_no_pass(self) -> None:
        """Test that the sign function works with good options."""
        signer = {"key_file_format": "pkcs12", "key_data": b64decode(TESTCERT1)}
        signature = {
            "type": "bare",
            "encoding": "binary",
            "hash_alg": "sha256",
        }
        data = "Data for testing signer".encode()
        pyopenssl_signer.sign(data, signature, signer)

    def test_proper_options_good_key_pass(self) -> None:
        """Test that the sign function works with good options."""
        signer = {"key_file_format": "pkcs12", "key_data": b64decode(TESTCERT2), "key_file_password": "password"}
        signature = {
            "type": "bare",
            "encoding": "binary",
            "hash_alg": "sha256",
        }
        data = "Data for testing signer".encode()
        pyopenssl_signer.sign(data, signature, signer)

    def test_proper_options_bad_key(self) -> None:
        """Test that the sign function raises an error with bad options."""
        # we're going to assume that we're
        with self.assertRaises(ValueError):
            signer = {"key_file_format": "pkcs12", "key_data": "hello there"}
            signature = {
                "type": "bare",
                "encoding": "binary",
                "hash_alg": "sha256",
            }
            pyopenssl_signer.sign(None, signature, signer)

    def test_invalid_type(self) -> None:
        """Test that the sign function raises an error with bad options."""
        # we're going to assume that we're
        with self.assertRaises(ValueError):
            signature = {
                "type": "bad_type",
            }
            pyopenssl_signer.sign(None, signature, {})

    def test_invalid_type_options(self) -> None:
        """Test that the sign function raises an error with bad options."""
        # we're going to assume that we're
        with self.assertRaises(ValueError):
            signature = {"type": "bare", "type_options": "not allowed"}
            pyopenssl_signer.sign(None, signature, {})
