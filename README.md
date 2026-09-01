# django-encrypted-field
Django custom field supporting different encryption options.

By default, this field will fall back to ChaCha20 Poly 1305 algorithm, as we consider the stronger one to have.

But the user has some other options to configure.

## Installation

There exist a pip package in the registry. Just issue the typical "install" command:

```
$ pip install django-encrypted-field
```

## Compatibility

- Python 3.9+
- Django 4.2, 5.0, 5.1, 5.2

## Configuration

Before using the EncryptedField in your projects, it is necessary to add some configuration variables to your settings. Please, remember to do so, as this is CRITICAL to have the maximum guarantees in terms of encryption.

* DJANGO_ENCRYPTED_FIELD_KEY: [OPTIONAL if using per-field keys] [BYTES] here you must define the encryption key. It must be 16, 24 or 32 bytes long and in bytes format. Like in `b'12345...'`.
* DJANGO_ENCRYPTED_FIELD_ALGORITHM: [OPTIONAL] [STRING] the default algorithm to be used, as defined in the code list for supported algorithms (see below). If not set, will default to ChaCha20 Poly 1305.

See an example:
```
DJANGO_ENCRYPTED_FIELD_KEY = b'12345678901234567890123456789012'
# Recommended: using the environment.
DJANGO_ENCRYPTED_FIELD_KEY = os.environ.get('ENV_DJANGO_ENCRYPTED_FIELD_KEY')
DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'CC20P'
DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'SS20'
...
DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'AGCM'
```

## Usage in a django project

The use of the custom field is easy. You don't need to add the package to the INSTALLED_APPS, so just include an import in your models and use the field directly.

For example, if you want to start the easy way, with the default encryption (ChaCha20 Poly 1305), follow these steps:

### First step: settings.py

Just configure the key:

```
DJANGO_ENCRYPTED_FIELD_KEY = os.environ.get('ENV_DJANGO_ENCRYPTED_FIELD_KEY')
```

### Second step: app/models.py

Take on mind the following restrictions:

* This field cannot be primary_key
* This field cannot be unique
* This field cannot be db_index

Now, import the field and add it to your very secret model:

```
from django.db import models
from encrypted_field import EncryptedField


class MySecretModel(models.Model):
    secret = EncryptedField()
```

### Third step: standard usage

Just use as any other field, but with these restrictions:

* You cannot perform useful searches in the field contents.
* The content is TEXT, formatted as JSON/dict with the required elements for encryption/decryption.

See the usage in a helper script (not a Django view). Encryption (just save):

```python
import os
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "your_project.settings")
from django.conf import settings
django.setup()

from app.models import MySecretModel

secret_instance = MySecretModel()
secret_instance.secret = 'A very secret message we want to store in database.'
secret_instance.save()
```

Decryption (just query the model):

```python
import os
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "your_project.settings")
from django.conf import settings
django.setup()

from app.models import MySecretModel

secret_instance = MySecretModel.objects.get(id=1)
print(
    "The SECRET=[{secret}]".format(secret=secret_instance.secret)
)
```

## Advanced usages

The previous example is the quick&easy way of using this custom field. But you may want to customize the way it will work.

### Encryption algorithms

As for the present release, the following algorithms are supported:

* ALGORITHM_CHACHA20_POLY1305 = 'CC20P' # Key size must be 32 bytes
* ALGORITHM_CHACHA20 = 'CC20' # Key size must be 32 bytes
* ALGORITHM_SALSA20 = 'SS20' # Key size must be 32 bytes
* ALGORITHM_AES_GCM = 'AGCM' # Key size must be 16, 24 or 32 bytes
* ALGORITHM_AES_SIV = 'ASIV' # Key size must be 16, 24 or 32 bytes
* ALGORITHM_AES_EAX = 'AEAX' # Key size must be 16, 24 or 32 bytes
* ALGORITHM_AES_CCM = 'ACCM' # Key size must be 16, 24 or 32 bytes
* ALGORITHM_AES_OCB = 'AOCB' # Key size must be 16, 24 or 32 bytes

The assigned text is a short name in text for the algorithm, to pass it in dictionaries and JSON objects, and is the value you should use if going to set the settings variable (remember, `DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'AGCM'`).

It is **VERY IMPORTANT** to define the variable if you are changing the algorithm in the field definition, as we will see below. Please, do remember this.

### Set a different algorithm for a field

When adding the field to the model, you can change the default algorithm if necessary. Just passing "algorithm" in the field definition:

```python
from django.db import models
from encrypted_field import EncryptedField


class MySecretModel(models.Model):
    secret = EncryptedField(algorithm='SS20')  # Will use Salsa20 algorithm.
```

You may want to make more difficult to attack the encryption just removing algorithm information from the database:

```python
from django.db import models
from encrypted_field import EncryptedField


class MySecretModel(models.Model):
    secret = EncryptedField(algorithm='SS20', hide_algorithm=True)  # Will use Salsa20 algorithm. HIDDEN.
```

So the encrypted results will be stored in the database without any reference to the algorithm that was used. If this is a use case you need, **PLEASE REMEMBER TO SET THE SETTINGS VARIABLE FOR THE ALGORITHM**.

In your_project/settings.py:

```python
DJANGO_ENCRYPTED_FIELD_KEY = os.environ.get('ENV_DJANGO_ENCRYPTED_FIELD_KEY')
DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'AGCM'
```

In app/models.py:

```python
from django.db import models
from encrypted_field import EncryptedField


class MySecretModel(models.Model):
    secret = EncryptedField(algorithm='AGCM', hide_algorithm=True)  # Will use AGCM algorithm. HIDDEN.
```

### Change the prepended header

If you want to change the default prepend header for some algorithms, you can pass a new header onto the field definition. See:

```python
from django.db import models
from encrypted_field import EncryptedField


class MySecretModel(models.Model):
    secret = EncryptedField(header=b'My custom header')
```

## Custom encryption keys

Starting with version 1.1.0, you can pass custom encryption keys at different levels, instead of relying solely on the global `settings.DJANGO_ENCRYPTED_FIELD_KEY`. This is useful when different fields or different users need to use different keys, for example, when an end user provides their own password interactively.

### Key resolution order

When encrypting or decrypting, the field resolves the key using the following priority (most specific wins):

1. **Per-instance key**: set `instance._encryption_key` on the model instance before saving.
2. **Per-field key**: pass `key=b'...'` when defining the `EncryptedField` in the model.
3. **Global settings key**: `settings.DJANGO_ENCRYPTED_FIELD_KEY` (the existing behavior).

If no key is found at any level, a `MissingKeyException` is raised.

### Per-field key

You can set a fixed key for a specific field at definition time. This key will be used for all encrypt/decrypt operations on that field, overriding the global settings key:

```python
from django.db import models
from encrypted_field import EncryptedField


class MySecretModel(models.Model):
    secret = EncryptedField(key=b'MyCustom32ByteKeyHere!!!!!123456')
```

The key must be in bytes format and have the correct length for the algorithm (32 bytes for ChaCha20/Salsa20, or 16/24/32 bytes for AES).

**Security note**: the `key` parameter is intentionally excluded from Django migrations. It will never be serialized into migration files.

### Per-instance key (interactive/dynamic)

For scenarios where the encryption key comes from user input or is determined at runtime (e.g., a user types their password in a form), you can set the key on the model instance before saving:

```python
from app.models import MySecretModel

# The user provides their key interactively
user_key = b'UserProvidedKey!UserProvidedKey!'  # 32 bytes

secret_instance = MySecretModel()
secret_instance._encryption_key = user_key
secret_instance.secret = 'A very secret message encrypted with the user key.'
secret_instance.save()
```

**Important**: when data is encrypted with a per-instance key, automatic decryption on retrieval (`MySecretModel.objects.get(...)`) will attempt to use the field-level key or the global settings key, which will fail if the data was encrypted with a different key. In this case, you need to decrypt manually (see below).

### Manual encrypt and decrypt with an arbitrary key

You can call `encrypt()` and `decrypt()` directly on the field, passing any key you want. This is the most flexible approach and is especially useful for data encrypted with per-instance keys:

```python
from app.models import MySecretModel

custom_key = b'AnyArbitraryKey!AnyArbitraryKey!'  # 32 bytes

# Get the field object from the model
field = MySecretModel._meta.get_field('secret')

# Encrypt manually
encrypted = field.encrypt('My secret data', key=custom_key)

# Decrypt manually
plaintext = field.decrypt(encrypted, key=custom_key)
print(plaintext)  # 'My secret data'
```

### Retrieving data encrypted with a per-instance key

When data was encrypted with a per-instance key, you need to read the raw encrypted value from the database and decrypt it manually:

```python
from django.db import connection
from app.models import MySecretModel

user_key = b'UserProvidedKey!UserProvidedKey!'  # The same key used for encryption

# Read the raw encrypted value from the database
with connection.cursor() as cursor:
    cursor.execute(
        'SELECT secret FROM app_mysecretmodel WHERE id = %s',
        [instance_id]
    )
    raw_encrypted = cursor.fetchone()[0]

# Decrypt with the user's key
field = MySecretModel._meta.get_field('secret')
plaintext = field.decrypt(raw_encrypted, key=user_key)
print(plaintext)
```

### Complete example: user-provided encryption

Here is a complete example of a workflow where users encrypt their data with their own key:

```python
import os
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "your_project.settings")
django.setup()

from django.db import connection
from app.models import MySecretModel

# --- Encryption (user provides key) ---
user_key = get_key_from_user()  # Your function to get the key from the user

instance = MySecretModel()
instance._encryption_key = user_key
instance.secret = 'Top secret user data'
instance.save()
saved_id = instance.id

# --- Decryption (user provides key again) ---
user_key = get_key_from_user()  # Ask for the key again

with connection.cursor() as cursor:
    cursor.execute(
        'SELECT secret FROM app_mysecretmodel WHERE id = %s',
        [saved_id]
    )
    raw_encrypted = cursor.fetchone()[0]

field = MySecretModel._meta.get_field('secret')
plaintext = field.decrypt(raw_encrypted, key=user_key)
print(plaintext)  # 'Top secret user data'
```

## Write paths and what gets encrypted

Every value that reaches the database column is encrypted exactly once, whatever the write path:

- `instance.save()` and `bulk_create()`: `pre_save()` encrypts using the resolved key (per-instance > per-field > settings). The model instance is **not** modified: after `save()` the attribute still holds the plaintext, and saving again re-encrypts from that plaintext (fresh nonce each time). `pre_save()` is idempotent and free of side effects, as required by Django 6.0, which may call it more than once per `save()`.
- `QuerySet.update(field='plaintext')` and `bulk_update()`: these bypass `pre_save()`, so `get_db_prep_save()` encrypts the value. There is no instance in this path, so **per-instance keys are not available here**; the per-field or settings key is used.
- Expressions (`F()`, `Case()`, ...) cannot be encrypted and are handed to Django unchanged.

When reading, `from_db_value()` decrypts with the per-field or settings key. If the stored value is not an envelope produced by this field (plaintext, corrupted or legacy data) the attribute is loaded as `None` and, with `DEBUG=True`, an error is logged.

## How the encryption/decryption key is used

The key is resolved at the moment each encryption/decryption operation is performed, following the resolution order described above. It is never stored in the database or in migration files.

A quick sketch of the process:

1. Create the model with an EncryptedField.
2. Create an instance like in `my_instance = MySecretModel()`
3. (Optional) Set a per-instance key: `my_instance._encryption_key = b'...'`
4. Save the instance: `my_instance.save()`
5. **ENCRYPTION STARTS**: the field resolves the key (per-instance > per-field > settings) and encrypts.
6. Retrieve from the database: `my_instance = MySecretModel.objects.get(id=1)`
7. **DECRYPTION STARTS**: the field resolves the key (per-field > settings) and decrypts. Note that per-instance keys are not available during automatic retrieval.

## Exceptions

Some custom exceptions have been created to be able to differentiate from generic ones.

### MissingKeyException

This exception will be raised when no key can be found at any level (per-instance, per-field, or settings).

### InvalidKeyFormatException

This exception will be raised when the key is not in bytes format. **Please, remember** the key must be bytes, not string.

### InvalidKeyLengthException

This exception will be raised when the key has not the required length. Remember:

- ChaCha20 Poly/ChaCha20/Salsa20: 32 bytes key length.
- AES algorithms: 16, 24 or 32 bytes key length.

### UnknownAlgorithmException

This exception will be raised when an unknown algorithm is passed to encrypt/decrypt.

### AESInvalidAlgorithmException

This exception will be raised when an unknown AES algorithm is passed to encrypt/decrypt. Typically, an invalid mode within the AES algorithm.
