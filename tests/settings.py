DEBUG = True
UNIT_TESTING = True
DJANGO_ENCRYPTED_FIELD_KEY = b'12345678901234567890123456789012'
DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'AGCM'

INSTALLED_APPS = [
    'tests'
]

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'db.tests.sqlite',
    }
}
