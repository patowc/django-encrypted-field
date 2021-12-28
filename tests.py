"""
Tests module for django-encrypted-field package.

"""
import os
import sys
import logging
import unittest

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
from django.conf import settings
django.setup()
from django.core.management import call_command  # pylint: disable=E0402


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
        self.assertNotEqual(settings.DJANGO_ENCRYPTED_FIELD_KEY, None)

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
        base_model = MyModel()
        base_model.seed = secret_message
        base_model.save()
        self.assertGreater(base_model.id, 0)
        test_base_instance = MyModel.objects.get(id=base_model.id)
        self.assertEqual(secret_message, test_base_instance.seed)

        base_model2 = MyModel2()
        base_model2.seed_hidden = secret_message
        base_model2.save()
        self.assertGreater(base_model2.id, 0)
        test_base_instance2 = MyModel2.objects.get(id=base_model2.id)
        self.assertEqual(secret_message, test_base_instance2.seed_hidden)

        base_model3 = MyModel3()
        base_model3.seed = secret_message
        base_model3.save()
        self.assertGreater(base_model3.id, 0)
        test_base_instance3 = MyModel3.objects.get(id=base_model3.id)
        self.assertEqual(secret_message, test_base_instance3.seed)

        base_model4 = MyModel4()
        base_model4.seed = secret_message
        base_model4.save()
        self.assertGreater(base_model4.id, 0)
        test_base_instance4 = MyModel4.objects.get(id=base_model4.id)
        self.assertEqual(secret_message, test_base_instance4.seed)

        base_model5 = MyModel5()
        base_model5.seed = secret_message
        base_model5.save()
        self.assertGreater(base_model5.id, 0)
        test_base_instance5 = MyModel5.objects.get(id=base_model5.id)
        self.assertEqual(secret_message, test_base_instance5.seed)

        base_model6 = MyModel6()
        base_model6.seed = secret_message
        base_model6.save()
        self.assertGreater(base_model6.id, 0)
        test_base_instance6 = MyModel6.objects.get(id=base_model6.id)
        self.assertEqual(secret_message, test_base_instance6.seed)

        base_model7 = MyModel7()
        base_model7.seed = secret_message
        base_model7.save()
        self.assertGreater(base_model7.id, 0)
        test_base_instance7 = MyModel7.objects.get(id=base_model7.id)
        self.assertEqual(secret_message, test_base_instance7.seed)

        base_model8 = MyModel8()
        base_model8.seed = secret_message
        base_model8.save()
        self.assertGreater(base_model8.id, 0)
        test_base_instance8 = MyModel8.objects.get(id=base_model8.id)
        self.assertEqual(secret_message, test_base_instance8.seed)

        base_model9 = MyModel9()
        base_model9.seed = secret_message
        base_model9.save()
        self.assertGreater(base_model9.id, 0)
        test_base_instance9 = MyModel9.objects.get(id=base_model9.id)
        self.assertEqual(secret_message, test_base_instance9.seed)


if __name__ == "__main__":
    # REMOVE database test files.
    try:
        os.remove("db.tests.sqlite")
    except:
        pass

    call_command('makemigrations', interactive=False)
    call_command('migrate', interactive=False)

    unittest.main()
