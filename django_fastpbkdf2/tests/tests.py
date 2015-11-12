from django.conf.global_settings import PASSWORD_HASHERS
from django.contrib.auth.hashers import (is_password_usable,
    check_password, make_password, get_hasher)
from django.test.utils import override_settings
from django.test import SimpleTestCase


from django_fastpbkdf2.hashers import (FastPBKDF2PasswordHasher,
    FastPBKDF2SHA1PasswordHasher)


@override_settings(PASSWORD_HASHERS=PASSWORD_HASHERS)
class TestUtilsHashPass(SimpleTestCase):

    def test_simple(self):
        encoded = make_password('letmein')
        self.assertTrue(encoded.startswith('pbkdf2_sha256$'))
        self.assertTrue(is_password_usable(encoded))
        self.assertTrue(check_password(u'letmein', encoded))
        self.assertFalse(check_password('letmeinz', encoded))

    def test_pkbdf2(self):
        encoded = make_password('letmein', 'seasalt', 'fastpbkdf2_sha256')
        self.assertEqual(encoded,
'pbkdf2_sha256$10000$seasalt$FQCNpiZpTb0zub+HBsH6TOwyRxJ19FwvjbweatNmK/Y=')
        self.assertTrue(is_password_usable(encoded))
        self.assertTrue(check_password(u'letmein', encoded))
        self.assertFalse(check_password('letmeinz', encoded))

    def test_low_level_pkbdf2(self):
        hasher = FastPBKDF2PasswordHasher()
        encoded = hasher.encode('letmein', 'seasalt')
        self.assertEqual(encoded,
'fastpbkdf2_sha256$30000$seasalt$tI4kYeTLVrgdxTAIgLktSixYYIhAP6NsMaxCyxZ8hIk=')
        self.assertTrue(hasher.verify('letmein', encoded))

    def test_low_level_pbkdf2_sha1(self):
        hasher = FastPBKDF2SHA1PasswordHasher()
        encoded = hasher.encode('letmein', 'seasalt')
        self.assertEqual(encoded,
'fastpbkdf2_sha1$30000$seasalt$pSio+VLfFP4bTfX28Hfio+Sce7Q=')
        self.assertTrue(hasher.verify('letmein', encoded))

    def test_upgrade(self):
        self.assertEqual('pbkdf2_sha256', get_hasher('default').algorithm)
        for algo in ('sha1', 'md5'):
            encoded = make_password('letmein', hasher=algo)
            state = {'upgraded': False}
            def setter(password):
                state['upgraded'] = True
            self.assertTrue(check_password('letmein', encoded, setter))
            self.assertTrue(state['upgraded'])

    def test_no_upgrade(self):
        encoded = make_password('letmein')
        state = {'upgraded': False}
        def setter():
            state['upgraded'] = True
        self.assertFalse(check_password('WRONG', encoded, setter))
        self.assertFalse(state['upgraded'])

    def test_no_upgrade_on_incorrect_pass(self):
        self.assertEqual('pbkdf2_sha256', get_hasher('default').algorithm)
        for algo in ('sha1', 'md5'):
            encoded = make_password('letmein', hasher=algo)
            state = {'upgraded': False}
            def setter():
                state['upgraded'] = True
            self.assertFalse(check_password('WRONG', encoded, setter))
            self.assertFalse(state['upgraded'])
