"""
Tests module for django-encrypted-field package.

"""
import os
import sys
import json
import logging
import unittest

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
from django.conf import settings
django.setup()
from django.core.management import call_command  # pylint: disable=E0402
from django.db import connection  # pylint: disable=E0402


logger = logging.getLogger(__name__)

app = 'tests'


from encrypted_field.fields import *  # pylint: disable=E0402
from tests.models import *  # pylint: disable=E0402


class AllTests(unittest.TestCase):
    def test_configuration(self):
        """
        Test configuration defaults.
        :return: nothing as is a test case.

        """
        self.assertEqual(settings.DEBUG, True)
        self.assertNotEqual(settings.DJANGO_ENCRYPTED_FIELD_KEY, None)
        self.assertNotEqual(settings.DJANGO_ENCRYPTED_FIELD_ALGORITHM, None)

    def test_environment(self):
        """
        Test we can retrieve from env, falling back on default values, and
        setting a value in the environment.

        :return: nothing as is a test case.

        """
        os.environ['ENV_DEBUG'] = 'True'
        test_debug = os.getenv('ENV_DEBUG', None)
        if test_debug:
            self.assertEqual(test_debug, 'True')
        else:
            self.assertEqual(1, 1)

    def test_models_exists(self):
        """
        Test for django models (MyModel, MyModel2,...).

        :return:  nothing as is a test case.

        """
        base_model = MyModel()
        self.assertNotEqual(base_model, None)

        base_model2 = MyModel2()
        self.assertNotEqual(base_model2, None)

        base_model3 = MyModel3()
        self.assertNotEqual(base_model3, None)

        base_model4 = MyModel4()
        self.assertNotEqual(base_model4, None)

        base_model5 = MyModel5()
        self.assertNotEqual(base_model5, None)

        base_model6 = MyModel6()
        self.assertNotEqual(base_model6, None)

        base_model7 = MyModel7()
        self.assertNotEqual(base_model7, None)

        base_model8 = MyModel8()
        self.assertNotEqual(base_model8, None)

        base_model9 = MyModel9()
        self.assertNotEqual(base_model9, None)

    def test_models_save(self):
        """
        Test for encrypted_field models now saving data.

        :return:  nothing as is a test case.

        """
        secret_message = 'A very critical secret.'

        settings.DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'CC20P'
        base_model = MyModel()
        base_model.seed = secret_message
        base_model.save()
        self.assertGreater(base_model.id, 0)
        test_base_instance = MyModel.objects.get(id=base_model.id)
        self.assertEqual(secret_message, test_base_instance.seed)

        settings.DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'CC20P'
        base_model2 = MyModel2()
        base_model2.seed_hidden = secret_message
        base_model2.save()
        self.assertGreater(base_model2.id, 0)
        test_base_instance2 = MyModel2.objects.get(id=base_model2.id)
        self.assertEqual(secret_message, test_base_instance2.seed_hidden)

        settings.DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'CC20'
        base_model3 = MyModel3()
        base_model3.seed = secret_message
        base_model3.save()
        self.assertGreater(base_model3.id, 0)
        test_base_instance3 = MyModel3.objects.get(id=base_model3.id)
        self.assertEqual(secret_message, test_base_instance3.seed)

        settings.DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'SS20'
        base_model4 = MyModel4()
        base_model4.seed = secret_message
        base_model4.save()
        self.assertGreater(base_model4.id, 0)
        test_base_instance4 = MyModel4.objects.get(id=base_model4.id)
        self.assertEqual(secret_message, test_base_instance4.seed)

        settings.DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'AGCM'
        base_model5 = MyModel5()
        base_model5.seed = secret_message
        base_model5.save()
        self.assertGreater(base_model5.id, 0)
        test_base_instance5 = MyModel5.objects.get(id=base_model5.id)
        self.assertEqual(secret_message, test_base_instance5.seed)

        settings.DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'ASIV'
        base_model6 = MyModel6()
        base_model6.seed = secret_message
        base_model6.save()
        self.assertGreater(base_model6.id, 0)
        test_base_instance6 = MyModel6.objects.get(id=base_model6.id)
        self.assertEqual(secret_message, test_base_instance6.seed)

        settings.DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'AEAX'
        base_model7 = MyModel7()
        base_model7.seed = secret_message
        base_model7.save()
        self.assertGreater(base_model7.id, 0)
        test_base_instance7 = MyModel7.objects.get(id=base_model7.id)
        self.assertEqual(secret_message, test_base_instance7.seed)

        settings.DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'ACCM'
        base_model8 = MyModel8()
        base_model8.seed = secret_message
        base_model8.save()
        self.assertGreater(base_model8.id, 0)
        test_base_instance8 = MyModel8.objects.get(id=base_model8.id)
        self.assertEqual(secret_message, test_base_instance8.seed)

        settings.DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'AOCB'
        base_model9 = MyModel9()
        base_model9.seed = secret_message
        base_model9.save()
        self.assertGreater(base_model9.id, 0)
        test_base_instance9 = MyModel9.objects.get(id=base_model9.id)
        self.assertEqual(secret_message, test_base_instance9.seed)

    def test_field_level_key(self):
        """
        Test for EncryptedField with a custom key passed at field definition.
        MyModel10 uses key=b'ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'.

        :return: nothing as is a test case.

        """
        secret_message = 'Field-level key secret.'

        base_model10 = MyModel10()
        base_model10.seed = secret_message
        base_model10.save()
        self.assertGreater(base_model10.id, 0)
        test_base_instance10 = MyModel10.objects.get(id=base_model10.id)
        self.assertEqual(secret_message, test_base_instance10.seed)

    def test_instance_level_key(self):
        """
        Test for EncryptedField with a per-instance key set interactively
        via model_instance._encryption_key.

        :return: nothing as is a test case.

        """
        secret_message = 'Instance-level key secret.'
        custom_key = b'InstanceKey1234567890ABCDEFGHIJK'

        # Encrypt with a per-instance key.
        base_model = MyModel()
        base_model._encryption_key = custom_key
        base_model.seed = secret_message
        base_model.save()
        self.assertGreater(base_model.id, 0)

        # Auto-decryption uses the settings key, which will fail to decrypt.
        # So we manually decrypt with the correct key.
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute(
                'SELECT seed FROM tests_mymodel WHERE id = %s',
                [base_model.id]
            )
            raw_encrypted = cursor.fetchone()[0]

        field = MyModel._meta.get_field('seed')
        decrypted = field.decrypt(raw_encrypted, key=custom_key)
        self.assertEqual(secret_message, decrypted)

    def test_manual_encrypt_decrypt(self):
        """
        Test manual encrypt/decrypt with an arbitrary key passed directly
        to the encrypt() and decrypt() methods.

        :return: nothing as is a test case.

        """
        secret_message = 'Manual encrypt/decrypt test.'
        custom_key = b'ManualKeyTesting1234567890ABCDEF'

        field = MyModel._meta.get_field('seed')
        encrypted = field.encrypt(secret_message, key=custom_key)
        decrypted = field.decrypt(encrypted, key=custom_key)
        self.assertEqual(secret_message, decrypted)

    def test_invalid_parameters(self):
        """
        Test for encrypted_field invalid prameters.

        :return:  nothing as is a test case.

        """
        secret_message = 'A very critical secret.'

        settings.DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'CC20P'
        # Bytes ok, wrong len 11 (must be 32)
        settings.DJANGO_ENCRYPTED_FIELD_KEY = b'12345678901'
        base_model = MyModel()
        base_model.seed = secret_message
        with self.assertRaises(InvalidKeyLengthException) as context:
            base_model.save()
        self.assertTrue('key must be 32 bytes/256 bit long' in str(context.exception))

        # Bytes wrong, len 32 OK
        settings.DJANGO_ENCRYPTED_FIELD_KEY = '12345678901234567890123456789012'
        base_model = MyModel()
        base_model.seed = secret_message
        with self.assertRaises(InvalidKeyFormatException) as context:
            base_model.save()
        self.assertTrue('must be BYTES' in str(context.exception))

        # Restore KEY to avoid conflicts with other tests.
        settings.DJANGO_ENCRYPTED_FIELD_KEY = b'12345678901234567890123456789012'

    def test_invalid_field_key_format(self):
        """
        Test that passing a non-bytes key to EncryptedField raises
        InvalidKeyFormatException.

        :return: nothing as is a test case.

        """
        with self.assertRaises(InvalidKeyFormatException):
            EncryptedField(key='not_bytes_key_here')

    def test_save_does_not_mutate_instance(self):
        """
        Regression test (1.1.1): pre_save() must not write the encrypted
        value back into the instance. After save() the attribute has to keep
        the plaintext, and a second save() must not double-encrypt.

        :return:  nothing as is a test case.

        """
        secret_message = 'Keep me in plaintext on the instance.'

        base_model = MyModel(seed=secret_message)
        base_model.save()
        self.assertEqual(base_model.seed, secret_message)

        # Second save() on the same instance (full and with update_fields).
        base_model.save()
        base_model.save(update_fields=['seed'])
        self.assertEqual(base_model.seed, secret_message)
        self.assertEqual(MyModel.objects.get(id=base_model.id).seed, secret_message)

        base_model.refresh_from_db()
        self.assertEqual(base_model.seed, secret_message)

        # bulk_create() goes through pre_save() as well.
        created = MyModel.objects.bulk_create([MyModel(seed=secret_message)])
        self.assertEqual(created[0].seed, secret_message)
        self.assertEqual(MyModel.objects.get(id=created[0].id).seed, secret_message)

    def test_save_stores_ciphertext(self):
        """
        Regression test (1.1.1): the database column must hold our JSON
        envelope, never the plaintext, for every write path.

        :return:  nothing as is a test case.

        """
        secret_message = 'Never in plaintext in the database.'

        def raw_value(pk):
            with connection.cursor() as cursor:
                cursor.execute('SELECT seed FROM tests_mymodel WHERE id = %s', [pk])
                return cursor.fetchone()[0]

        def assert_encrypted(pk):
            raw = raw_value(pk)
            self.assertNotEqual(raw, secret_message)
            self.assertNotIn(secret_message, raw)
            self.assertIn('ciphertext', json.loads(raw))

        # Model.save()
        base_model = MyModel.objects.create(seed=secret_message)
        assert_encrypted(base_model.id)

        # QuerySet.update(): does not call pre_save(), only get_db_prep_save().
        MyModel.objects.filter(id=base_model.id).update(seed='updated ' + secret_message)
        raw = raw_value(base_model.id)
        self.assertNotIn(secret_message, raw)
        self.assertIn('ciphertext', json.loads(raw))
        self.assertEqual(MyModel.objects.get(id=base_model.id).seed, 'updated ' + secret_message)

        # QuerySet.bulk_update(): Value(..., for_save=True) -> get_db_prep_save().
        base_model.seed = 'bulk ' + secret_message
        MyModel.objects.bulk_update([base_model], ['seed'])
        raw = raw_value(base_model.id)
        self.assertNotIn(secret_message, raw)
        self.assertIn('ciphertext', json.loads(raw))
        self.assertEqual(MyModel.objects.get(id=base_model.id).seed, 'bulk ' + secret_message)

    def test_per_instance_key_does_not_mutate_instance(self):
        """
        Regression test (1.1.1): same as test_save_does_not_mutate_instance
        but using a per-instance key.

        :return:  nothing as is a test case.

        """
        secret_message = 'Per-instance secret.'
        user_key = b'USERKEYUSERKEYUSERKEYUSERKEY1234'

        base_model = MyModel(seed=secret_message)
        base_model._encryption_key = user_key
        base_model.save()
        self.assertEqual(base_model.seed, secret_message)

        base_model.save()
        self.assertEqual(base_model.seed, secret_message)

        field = MyModel._meta.get_field('seed')
        with connection.cursor() as cursor:
            cursor.execute('SELECT seed FROM tests_mymodel WHERE id = %s', [base_model.id])
            raw = cursor.fetchone()[0]
        self.assertEqual(field.decrypt(raw, key=user_key), secret_message)

    def test_pre_save_is_idempotent(self):
        """
        Regression test (1.1.1): Django 6.0 may call Field.pre_save() more
        than once while saving a single instance, so it must be idempotent
        and free of side effects. Calling it repeatedly must leave the
        instance untouched and every result must decrypt to the plaintext
        with a single decrypt() (no double encryption).

        :return:  nothing as is a test case.

        """
        secret_message = 'pre_save may run twice per save() in Django 6.0.'
        field = MyModel._meta.get_field('seed')

        base_model = MyModel(seed=secret_message)
        first = field.pre_save(base_model, add=True)
        second = field.pre_save(base_model, add=True)
        self.assertEqual(base_model.seed, secret_message)
        self.assertEqual(field.decrypt(first), secret_message)
        self.assertEqual(field.decrypt(second), secret_message)

        # What Django does next: get_db_prep_save() on the pre_save() result
        # must not encrypt again.
        prepared = field.get_db_prep_save(second, connection)
        self.assertEqual(prepared, second)
        self.assertEqual(field.decrypt(prepared), secret_message)

        # Full round trip (whatever the number of pre_save() calls Django makes).
        base_model.save()
        self.assertEqual(base_model.seed, secret_message)
        self.assertEqual(MyModel.objects.get(id=base_model.id).seed, secret_message)

    def test_decrypt_invalid_payload(self):
        """
        Regression test (1.1.1): decrypt() must return None for a payload that
        is not our JSON envelope, both with DEBUG=True and DEBUG=False
        (previously it crashed with AttributeError when DEBUG=False).

        :return:  nothing as is a test case.

        """
        field = MyModel._meta.get_field('seed')
        original_debug = settings.DEBUG
        try:
            for debug in (True, False):
                settings.DEBUG = debug
                self.assertIsNone(field.decrypt('this is plaintext, not JSON'))
                self.assertIsNone(field.decrypt('[1, 2, 3]'))
                self.assertIsNone(field.from_db_value('this is plaintext, not JSON', None, connection))
        finally:
            settings.DEBUG = original_debug


if __name__ == "__main__":
    # REMOVE database test files.
    try:
        os.remove("db.tests.sqlite")
    except:
        pass

    call_command('makemigrations', interactive=False)
    call_command('migrate', interactive=False)

    unittest.main()
