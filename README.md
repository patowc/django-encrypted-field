# django-encrypted-field
Django custom field supporting different encryption options.

By default, this field will fall back to ChaCha20 Poly 1305 algorithm, as we consider the stronger one to have.

But the user has some other options to configure.

## Installation

There exist a pip package in the registry. Just issue the typical "install" command:

```
$ pip install django-encrypted-field
```

## Configuration

Before using the EncryptedField in your projects, it is necessary to add some configuration variables to your settings. Please, remember to do so, as this is CRITICAL to have the maximum guarantees in terms of encryption.

* DJANGO_ENCRYPTED_FIELD_KEY: [MANDATORY] [BYTES] here you must define the encryption key. It must be 16, 24 or 32 bytes long and in bytes format. Like in `b'12345...'`.
* DJANGO_ENCRYPTED_FIELD_ALGORITHM: [OPTIONAL] [STRING] the default algorithm to be used, as defined in the code list for supported algoritms (see below). If not set, will default to ChaCha20 Poly 1305.

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

The use of the custom field is easy. You don't need to add the packaged to the INSTALLED_APPS, so just include an import in your models and use the field directly.

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

```
# -*- coding: utf-8 -*-
#!/usr/bin/python
import os
import sys 
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

```
# -*- coding: utf-8 -*-
#!/usr/bin/python
import os
import sys 
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

The assigned text is a short name in text for the algorithm, to pass it in dictionaries and JSON objects, and is the value you should use if going to set the settings variable (remember, `DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'AGCM''`).

It is **VERY IMPORTANT** to define the variable if you are changing the algorithm in the field definition, as we will see below. Please, do remember this.

### Set a different algorithm for a field

When adding the field to the model, you can change the default algorithm if necessary. Just passing "algorithm" in the field definition:

```
from django.db import models
from encrypted_field import EncryptedField


class MySecretModel(models.Model):
    secret = EncryptedField(algorithm='SS20')  # Will use Salsa20 algorithm.
```

You may want to make more difficult to attack the encryption just removing algorithm information from the database:

```
from django.db import models
from encrypted_field import EncryptedField


class MySecretModel(models.Model):
    secret = EncryptedField(algorithm='SS20', hide_algorithm=True)  # Will use Salsa20 algorithm. HIDDEN.
```

So the encrypted results will be stored in the database without any reference to the algorithm that was used. If this is a use case you need, **PLEASE REMEMBER TO SET THE SETTINGS VARIABLE FOR THE ALGORITHM**.

In your_project/settings.py:

```
DJANGO_ENCRYPTED_FIELD_KEY = os.environ.get('ENV_DJANGO_ENCRYPTED_FIELD_KEY')
DJANGO_ENCRYPTED_FIELD_ALGORITHM = 'AGCM'
```

In app/models.py:

```
from django.db import models
from encrypted_field import EncryptedField


class MySecretModel(models.Model):
    secret = EncryptedField(algorithm='AGCM', hide_algorithm=True)  # Will use AGCM algorithm. HIDDEN.
```

### Change the prepended header

If you want to change the default prepend header for some algorithms, you can pass a new header onto the field definition. See:

```
from django.db import models
from encrypted_field import EncryptedField


class MySecretModel(models.Model):
    secret = EncryptedField(header='My custom header')
```

### How the encryption/decryption key is used

There is no way to set the key in the field, so the key is never used in a persistent way. Instead, everytime time an encryption/decryption operation is made, the settings variable will be checked immediately.

A quick sketch of the process may be:

1. Create the model with an EncryptedField.
2. Create an instance like in `my_instance = MySecretModel()`
3. Save the instance: `my_instance.save()`
4. **ENCRYPTION STARTS**: the field will invoke the encryption scheme reading the key from `settings.DJANGO_ENCRYPTED_FIELD_KEY`.
5. Retrive from the database: `my_instance = MySecretModel.objects.get(id=1)`
6. **DECRYPTION STARTS**: the field will invoke the decryption scheme reading the key from `settings.DJANGO_ENCRYPTED_FIELD_KEY`. 

## Exceptions

Some custom exceptions have been created to be able to differentiate from generic ones.

### MissingKeyException

This exception will be raised when there is no DJANGO_ENCRYPTED_FIELD_KEY in settings.

### InvalidKeyFormatException

This exception will be raised when DJANGO_ENCRYPTED_FIELD_KEY in settings is not bytes. **Please, remember** this key is bytes not string.

### InvalidKeyLengthException

This exception will be raised when DJANGO_ENCRYPTED_FIELD_KEY in settings is has not the required length. Remember:

- Chacha20 Poly/ChaCha20/Salsa20: 32 bytes key length.
- AES algorithms: 16, 24 or 32 bytes key length.

### UnknownAlgorithmException

This exception will be raised when an unknown algorithm is passed to encrypt/decrypt.

### AESInvalidAlgorithmException

This exception will be raised when an unknown AES algorithm is passed to encrypt/decrypt. Typically, an invalid mode within the AES algorithm.
