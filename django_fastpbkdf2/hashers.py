# -*- coding: utf-8 -*-
"""Django password hasher using a fast PBKDF2 implementation (fastpbkdf2)."""

import base64
from collections import OrderedDict

from django.contrib.auth.hashers import (BasePasswordHasher, mask_hash)
try:
    from django.contrib.auth.hashers import force_bytes
except ImportError:
    from django.utils.encoding import smart_str as force_bytes
from django.utils.crypto import constant_time_compare
from django.utils.translation import ugettext_noop as _
from fastpbkdf2 import pbkdf2_hmac


class FastPBKDF2PasswordHasher(BasePasswordHasher):
    """
    Secure password hashing using the PBKDF2 algorithm (recommended)

    Configured to use PBKDF2 + HMAC + SHA256.
    The result is a 64 byte binary string.  Iterations may be changed
    safely but you must rename the algorithm if you change SHA256.
    """
    iterations = 30000
    algorithm = "fastpbkdf2_sha256"
    digest = "sha256"

    def encode(self, password, salt, iterations=None):
        assert password
        assert salt and '$' not in salt
        if not iterations:
            iterations = self.iterations
        hash = pbkdf2_hmac(self.digest, force_bytes(password),
                           force_bytes(salt), iterations)
        hash = base64.b64encode(hash).strip().decode('utf-8')
        return "%s$%d$%s$%s" % (self.algorithm, iterations, salt, hash)

    def verify(self, password, encoded):
        algorithm, iterations, salt, hash = encoded.split('$', 3)
        assert algorithm == self.algorithm
        encoded_2 = self.encode(password, salt, int(iterations))
        return constant_time_compare(encoded, encoded_2)

    def safe_summary(self, encoded):
        algorithm, salt, hash = encoded.split('$', 2)
        assert algorithm == self.algorithm
        return OrderedDict([
            (_('algorithm'), algorithm),
            (_('salt'), mask_hash(salt, show=2)),
            (_('hash'), mask_hash(hash)),
        ])


class FastPBKDF2SHA1PasswordHasher(FastPBKDF2PasswordHasher):
    """
    Alternate PBKDF2 hasher which uses SHA1, the default PRF
    recommended by PKCS #5. This is compatible with other
    implementations of PBKDF2, such as openssl's
    PKCS5_PBKDF2_HMAC_SHA1().
    """
    algorithm = "fastpbkdf2_sha1"
    digest = "sha1"
