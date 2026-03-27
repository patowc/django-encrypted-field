"""
This file includes all the details and definitions for a model.EncryptedField
that can be used in django projects.

This version uses ChaCha20 Poly1305 algorithm by default, and supports
ChaCha20, Salsa20, AES in modes GCM, SIV, EAX, CCM and OCB.

It is easy to use:
(1) ~$ pip install django-encrypted-field
(2) from encrypted_field import EncryptedField
(3) class MyModel(models.Model):
        encrypted_field = EncryptedField()

Now, whenever you save or retrieve values they will be managed through an
encryption-decryption process transparent to the user.

You can also pass a custom key per field or per instance:
(a) class MyModel(models.Model):
        encrypted_field = EncryptedField(key=b'32_byte_key_here............')

(b) obj = MyModel()
    obj._encryption_key = b'user_provided_32byte_key........'
    obj.secret = "plaintext"
    obj.save()
"""
import typing
import json
import logging

from base64 import b64encode, b64decode
from Cryptodome.Cipher import (
    ChaCha20_Poly1305, ChaCha20, Salsa20,
    AES
)
from Cryptodome.Random import get_random_bytes

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models


# Try to avoid log-name-context collisions defaulting to __name__
logger = logging.getLogger(__name__)


__all__ = [
    'EncryptedField',
    'MissingKeyException',
    'InvalidKeyFormatException',
    'InvalidKeyLengthException',
    'UnknownAlgorithmException',
    'AESInvalidAlgorithmException'
]


# Default algorithm.
ALGORITHM_CHACHA20_POLY1305 = 'CC20P'
ALGORITHM_CHACHA20 = 'CC20'
ALGORITHM_SALSA20 = 'SS20'

ALGORITHM_AES_GCM = 'AGCM'
ALGORITHM_AES_SIV = 'ASIV'
ALGORITHM_AES_EAX = 'AEAX'
ALGORITHM_AES_CCM = 'ACCM'
ALGORITHM_AES_OCB = 'AOCB'

AES_KEY_SIZES = (
    ('A128', '128 bits / 16 bytes long'),
    ('A192', '192 bits / 24 bytes long'),
    ('A256', '256 bits / 32 bytes long'),
)

AES_VALID_KEY_SIZES_IN_LEN = [16, 24, 32]


ENCRYPTION_ALGORITHM = (
    (ALGORITHM_CHACHA20_POLY1305, 'ChaCha20 Poly1305'),
    (ALGORITHM_CHACHA20, 'ChaCha20'),
    (ALGORITHM_SALSA20, 'Salsa20'),
    (ALGORITHM_AES_GCM, 'AES GCM'),
    (ALGORITHM_AES_SIV, 'AES SIV'),
    (ALGORITHM_AES_EAX, 'AEX EAX'),
    (ALGORITHM_AES_CCM, 'AES CCM'),
    (ALGORITHM_AES_OCB, 'AES OCB'),
)


ALGORITHM_AES_ALGORITHMS = [
    ALGORITHM_AES_GCM,
    ALGORITHM_AES_SIV,
    ALGORITHM_AES_EAX,
    ALGORITHM_AES_CCM,
    ALGORITHM_AES_OCB
]


ALLOWED_ENCRYPTION_ALGORITHMS = [
    ALGORITHM_CHACHA20_POLY1305,
    ALGORITHM_CHACHA20,
    ALGORITHM_SALSA20,
    ALGORITHM_AES_GCM,
    ALGORITHM_AES_SIV,
    ALGORITHM_AES_EAX,
    ALGORITHM_AES_CCM,
    ALGORITHM_AES_OCB,
]


# Added specific exception classes to be able to differentiate from
# generic ones.
class MissingKeyException(Exception):
    pass


class InvalidKeyFormatException(Exception):
    pass


class InvalidKeyLengthException(Exception):
    pass


class UnknownAlgorithmException(Exception):
    pass


class AESInvalidAlgorithmException(Exception):
    pass


##############################################################################
# Encryption primitives. Parameters are typed (type hintin) and all the
# required details to be able to decreyt must be in the dictionary:
#     encrypted_data
#
# For example:
#     encrypted_data['nonce']
#     encrypted_data['header']
#     encrypted_data['tag']
#     ...
##############################################################################
def encrypt_chacha20_poly(data: str, header: bytes, key: bytes, hide_algorithm: bool = False) -> str:
    """
    Primitive to encrypt with ChaCha20 Poly1305.

    This is the default if not changed when creating the field. It is an
    stream cipher with authenticated data, to prevent integrity problems.

    :param data: plaintext data as string.
    :param header: a header to prepend to the plaintext message. Bytes.
    :param key: the hey (must be 32 bytes long). Bytes.
    :param hide_algorithm: set to True if we want to remove details about
    the algorithm in the database.
    :return: a string including a JSON/Dict object with the results.
    """
    # key must be BYTES
    if isinstance(key, (bytes, bytearray)) is not True:
        if settings.DEBUG is True:
            logger.error(
                'encrypt_chacha20_poly: key must be BYTES.'
            )
        raise InvalidKeyLengthException(
            'encrypt_chacha20_poly: key must be BYTES.'
        )

    # key must be 32 bytes long.
    key_len = len(key)
    if key_len != 32:
        if settings.DEBUG is True:
            logger.error(
                'encrypt_chacha20_poly: key must be 32 bytes/256 bit long. You passed [%d] bytes.' % key_len
            )
        raise InvalidKeyLengthException(
            'encrypt_chacha20_poly: key must be 32 bytes/256 bit long. You passed [%d] bytes.' % key_len
        )

    algorithm = ALGORITHM_CHACHA20_POLY1305
    cipher = ChaCha20_Poly1305.new(key=key)
    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(str.encode(data))

    dict_values = dict()
    # Nonce will be 12 bytes long for ChaCha20 Poly1305 by default.
    # In future releases will add support for XChaCha passing 24 bytes.
    dict_values['nonce'] = b64encode(cipher.nonce).decode('utf-8')
    dict_values['header'] = b64encode(header).decode('utf-8')
    dict_values['ciphertext'] = b64encode(ciphertext).decode('utf-8')
    # Tag must be used to validate the integrity.
    dict_values['tag'] = b64encode(tag).decode('utf-8')

    if hide_algorithm is False:
        dict_values['algorithm'] = algorithm

    return json.dumps(dict_values)


def decrypt_chacha20_poly(encrypted_data: dict, key: bytes) -> str:
    """
    Primitive to decrypt with ChaCha20 Poly1305.

    This is the default if not changed when creating the field. It is an
    stream cipher with authenticated data, to prevent integrity problems.

    encrypted_data will have:
    - 'nonce', 'header', 'ciphertext' and 'tag'.

    :param encrypted_data: the dictionary with all relevant details to be
    to decrypt.
    :param key: the hey (must be 32 bytes long). Bytes.
    :return: the original plaintext as string.
    """
    # key must be BYTES
    if isinstance(key, (bytes, bytearray)) is not True:
        if settings.DEBUG is True:
            logger.error(
                'decrypt_chacha20_poly: key must be BYTES.'
            )
        raise InvalidKeyLengthException(
            'decrypt_chacha20_poly: key must be BYTES.'
        )

    # key must be 32 bytes long.
    key_len = len(key)
    if key_len != 32:
        if settings.DEBUG is True:
            logger.error(
                'decrypt_chacha20_poly: key must be 32 bytes/256 bit long. You passed [%d] bytes.' % key_len
            )
        raise InvalidKeyLengthException(
            'decrypt_chacha20_poly: key must be 32 bytes/256 bit long. You passed [%d] bytes.' % key_len
        )

    nonce = b64decode(encrypted_data['nonce'])
    header = b64decode(encrypted_data['header'])
    ciphertext = b64decode(encrypted_data['ciphertext'])
    tag = b64decode(encrypted_data['tag'])

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    cipher.update(header)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


def encrypt_chacha20(data: str, key: bytes, hide_algorithm: bool = False) -> str:
    """
    Primitive to encrypt with ChaCha20.

    It is an stream cipher.

    :param data: plaintext data as string.
    :param key: the hey (must be 32 bytes long). Bytes.
    :param hide_algorithm: set to True if we want to remove details about
    the algorithm in the database.
    :return: a string including a JSON/Dict object with the results.
    """
    # key must be BYTES
    if isinstance(key, (bytes, bytearray)) is not True:
        if settings.DEBUG is True:
            logger.error(
                'encrypt_chacha20: key must be BYTES.'
            )
        raise InvalidKeyLengthException(
            'encrypt_chacha20: key must be BYTES.'
        )

    # key must be 32 bytes long.
    key_len = len(key)
    if key_len != 32:
        if settings.DEBUG is True:
            logger.error(
                'encrypt_chacha20: key must be 32 bytes/256 bit long. You passed [%d] bytes.' % key_len
            )
        raise InvalidKeyLengthException(
            'encrypt_chacha20: key must be 32 bytes/256 bit long. You passed [%d] bytes.' % key_len
        )

    algorithm = ALGORITHM_CHACHA20
    cipher = ChaCha20.new(key=key)
    ciphertext = cipher.encrypt(str.encode(data))

    dict_values = dict()
    # Nonce will be 8 bytes long for ChaCha20 by default.
    # In future releases will add support for XChaCha passing 24 bytes.
    dict_values['nonce'] = b64encode(cipher.nonce).decode('utf-8')
    dict_values['ciphertext'] = b64encode(ciphertext).decode('utf-8')

    if hide_algorithm is False:
        dict_values['algorithm'] = algorithm

    return json.dumps(dict_values)


def decrypt_chacha20(encrypted_data: dict, key: bytes) -> str:
    """
    Primitive to decrypt with ChaCha20.

    It is an stream cipher.

    encrypted_data will have:
    - 'nonce' and 'ciphertext'.

    :param encrypted_data: the dictionary with all relevant details to be
    to decrypt.
    :param key: the hey (must be 32 bytes long). Bytes.
    :return: the original plaintext as string.
    """
    # key must be BYTES
    if isinstance(key, (bytes, bytearray)) is not True:
        if settings.DEBUG is True:
            logger.error(
                'decrypt_chacha20: key must be BYTES.'
            )
        raise InvalidKeyLengthException(
            'decrypt_chacha20: key must be BYTES.'
        )

    # key must be 32 bytes long.
    key_len = len(key)
    if key_len != 32:
        if settings.DEBUG is True:
            logger.error(
                'decrypt_chacha20: key must be 32 bytes/256 bit long. You passed [%d] bytes.' % key_len
            )
        raise InvalidKeyLengthException(
            'decrypt_chacha20: key must be 32 bytes/256 bit long. You passed [%d] bytes.' % key_len
        )
    nonce = b64decode(encrypted_data['nonce'])
    ciphertext = b64decode(encrypted_data['ciphertext'])
    cipher = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode("utf-8")


def encrypt_salsa20(data: str, key: bytes, hide_algorithm: bool = False) -> str:
    """
    Primitive to encrypt with Salsa20.

    It is an stream cipher.

    :param data: plaintext data as string.
    :param key: the hey (must be 32 bytes long). Bytes.
    :param hide_algorithm: set to True if we want to remove details about
    the algorithm in the database.
    :return: a string including a JSON/Dict object with the results.
    """
    # key must be BYTES
    if isinstance(key, (bytes, bytearray)) is not True:
        if settings.DEBUG is True:
            logger.error(
                'encrypt_salsa20: key must be BYTES.'
            )
        raise InvalidKeyLengthException(
            'encrypt_salsa20: key must be BYTES.'
        )

    # key must be 32 bytes long.
    key_len = len(key)
    if key_len != 32:
        if settings.DEBUG is True:
            logger.error(
                'encrypt_salsa20: key must be 32 bytes/256 bit long. You passed [%d] bytes.' % key_len
            )
        raise InvalidKeyLengthException(
            'encrypt_salsa20: key must be 32 bytes/256 bit long. You passed [%d] bytes.' % key_len
        )

    algorithm = ALGORITHM_SALSA20
    cipher = Salsa20.new(key=key)
    ciphertext = cipher.encrypt(str.encode(data))

    dict_values = dict()
    # Nonce will be 8 bytes long for ChaCha20 by default.
    # In future releases will add support for XChaCha passing 24 bytes.
    dict_values['nonce'] = b64encode(cipher.nonce).decode('utf-8')
    dict_values['ciphertext'] = b64encode(ciphertext).decode('utf-8')

    if hide_algorithm is False:
        dict_values['algorithm'] = algorithm

    return json.dumps(dict_values)


def decrypt_salsa20(encrypted_data: dict, key: bytes) -> str:
    """
    Primitive to decrypt with Salsa20.

    It is an stream cipher.

    encrypted_data will have:
    - 'nonce' and 'ciphertext'.

    :param encrypted_data: the dictionary with all relevant details to be
    to decrypt.
    :param key: the hey (must be 32 bytes long). Bytes.
    :return: the original plaintext as string.
    """
    # key must be BYTES
    if isinstance(key, (bytes, bytearray)) is not True:
        if settings.DEBUG is True:
            logger.error(
                'decrypt_salsa20: key must be BYTES.'
            )
        raise InvalidKeyLengthException(
            'decrypt_salsa20: key must be BYTES.'
        )

    # key must be 32 bytes long.
    key_len = len(key)
    if key_len != 32:
        if settings.DEBUG is True:
            logger.error(
                'decrypt_salsa20: key must be 32 bytes/256 bit long. You passed [%d] bytes.' % key_len
            )
        raise InvalidKeyLengthException(
            'decrypt_salsa20: key must be 32 bytes/256 bit long. You passed [%d] bytes.' % key_len
        )
    nonce = b64decode(encrypted_data['nonce'])
    ciphertext = b64decode(encrypted_data['ciphertext'])
    cipher = Salsa20.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode("utf-8")


def encrypt_aes(data: str, header: bytes, key: bytes,
                algorithm: str = ALGORITHM_AES_GCM, hide_algorithm: bool = False) -> str:
    """
    Primitive to encrypt with AES in several modes.

    This is the default if not changed when creating the field. It is an
    stream cipher with authenticated data, to prevent integrity problems.

    :param data: plaintext data as string.
    :param header: a header to prepend to the plaintext message. Bytes.
    :param algorithm: a string. Default to ALGORITHM_AES_GCM and must be a
    value within ALGORITHM_AES_ALGORITHMS.
    :param key: the hey (must be 32 bytes long). Bytes.
    :param hide_algorithm: set to True if we want to remove details about
    the algorithm in the database.
    :return: a string including a JSON/Dict object with the results.
    """
    # key must be BYTES
    if isinstance(key, (bytes, bytearray)) is not True:
        if settings.DEBUG is True:
            logger.error(
                'encrypt_aes: key must be BYTES.'
            )
        raise InvalidKeyLengthException(
            'encrypt_aes: key must be BYTES.'
        )

    # key must be 16, 24 or 32 bytes long.
    key_len = len(key)
    if key_len not in AES_VALID_KEY_SIZES_IN_LEN:
        if settings.DEBUG is True:
            logger.error(
                'encrypt_AES: key must be 16, 24 or 32 bytes bit long. You passed [%d] bytes.' % key_len
            )
        raise InvalidKeyLengthException(
            'encrypt_AES: key must be 16, 24 or 32 bytes bit long. You passed [%d] bytes.' % key_len
        )

    # Default mode.
    mode = AES.MODE_GCM

    if algorithm == ALGORITHM_AES_GCM:
        mode = AES.MODE_GCM
    elif algorithm == ALGORITHM_AES_SIV:
        mode = AES.MODE_SIV
    elif algorithm == ALGORITHM_AES_EAX:
        mode = AES.MODE_EAX
    elif algorithm == ALGORITHM_AES_CCM:
        mode = AES.MODE_CCM
    elif algorithm == ALGORITHM_AES_OCB:
        mode = AES.MODE_OCB
    else:
        if settings.DEBUG is True:
            logger.error(
                'encrypt_AES: invalid algorithm passed [%s].' % str(algorithm)
            )
        raise AESInvalidAlgorithmException(
            'encrypt_AES: invalid algorithm passed [%s].' % str(algorithm)
        )

    if getattr(settings, 'UNIT_TESTING', False) is True:
        logger.critical('encrypt_AES: header=[%s] MODE=[%s]' % (header, mode))

    if algorithm == ALGORITHM_AES_SIV:
        # SIV without a nonce becomes DETERMINISTIC, and we don't want that.
        # So we generate a nonce with get_random_bytes
        cipher = AES.new(key=key, mode=mode, nonce=get_random_bytes(16))
    else:
        cipher = AES.new(key=key, mode=mode)

    cipher.update(header)
    ciphertext, tag = cipher.encrypt_and_digest(str.encode(data))

    dict_values = dict()
    dict_values['nonce'] = b64encode(cipher.nonce).decode('utf-8')
    dict_values['header'] = b64encode(header).decode('utf-8')
    dict_values['ciphertext'] = b64encode(ciphertext).decode('utf-8')
    # Tag must be used to validate the integrity.
    dict_values['tag'] = b64encode(tag).decode('utf-8')

    if hide_algorithm is False:
        dict_values['algorithm'] = algorithm

    return json.dumps(dict_values)


def decrypt_aes(encrypted_data: dict, key: bytes) -> str:
    """
    Primitive to decrypt with AES in different modes.

    It is an stream cipher with authenticated data.

    encrypted_data will have:
    - 'nonce', 'header', 'ciphertext' and 'tag'.

    :param encrypted_data: the dictionary with all relevant details to be
    to decrypt.
    :param key: the hey (must be 32 bytes long). Bytes.
    :return: the original plaintext as string.
    """
    # key must be BYTES
    if isinstance(key, (bytes, bytearray)) is not True:
        if settings.DEBUG is True:
            logger.error(
                'decrypt_aes: key must be BYTES.'
            )
        raise InvalidKeyLengthException(
            'decrypt_aes: key must be BYTES.'
        )

    # key must be 16, 24 or 32 bytes long.
    key_len = len(key)
    if key_len not in AES_VALID_KEY_SIZES_IN_LEN:
        if settings.DEBUG is True:
            logger.error(
                'decrypt_aes: key must be 16, 24 or 32 bytes bit long. You passed [%d] bytes.' % key_len
            )
        raise InvalidKeyLengthException(
            'decrypt_aes: key must be 16, 24 or 32 bytes bit long. You passed [%d] bytes.' % key_len
        )

    mode = None
    nonce = b64decode(encrypted_data['nonce'])
    header = b64decode(encrypted_data['header'])
    ciphertext = b64decode(encrypted_data['ciphertext'])
    tag = b64decode(encrypted_data['tag'])
    algorithm = encrypted_data['algorithm']

    if getattr(settings, 'UNIT_TESTING', False) is True:
        logger.critical('decrypt_AES: using algorithm [%s].' % algorithm)
        logger.critical('decrypt_AES: Encrypted data [%s].' % encrypted_data)

    if algorithm == ALGORITHM_AES_GCM:
        mode = AES.MODE_GCM
    elif algorithm == ALGORITHM_AES_SIV:
        mode = AES.MODE_SIV
    elif algorithm == ALGORITHM_AES_EAX:
        mode = AES.MODE_EAX
    elif algorithm == ALGORITHM_AES_CCM:
        mode = AES.MODE_CCM
    elif algorithm == ALGORITHM_AES_OCB:
        mode = AES.MODE_OCB
    else:
        if settings.DEBUG is True:
            logger.error(
                'decrypt_AES: invalid algorithm passed [%s].' % str(algorithm)
            )
        raise AESInvalidAlgorithmException(
            'decrypt_AES: invalid algorithm passed [%s].' % str(algorithm)
        )

    cipher = AES.new(key, mode, nonce=nonce)
    cipher.update(header)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")


class EncryptedField(models.Field):
    """
    This is the models.Field object for django model. It will behave as a
    TextField in every database related way, but passing through encrypt
    and decrypt processes when storing and retrieving data.

    Some options can be configured in the __init__ for the field, with a
    special interest in:

    - header: if we want to fix the header when setting the field.
    - algorithm: if we want to pass the algorithm. If not passed, will
    default to ALGORITHM_CHACHA20_POLY1305.
    - hide_algorithm: if we want to omit the algorithm details in the db,
    falling back to read a settings variable to confirm which one is in place.
    - key: if we want to pass a custom encryption key for this field,
    instead of using the global settings.DJANGO_ENCRYPTED_FIELD_KEY.

    Key resolution order (most specific wins):
    1. Per-instance: instance._encryption_key attribute (set interactively)
    2. Per-field: EncryptedField(key=b'...')
    3. Global: settings.DJANGO_ENCRYPTED_FIELD_KEY
    """
    description: str = 'An encrypted field that uses ChaCha20 poly1305.'
    _algorithm: typing.Optional[str] = ALGORITHM_CHACHA20_POLY1305
    _hide_algorithm: typing.Optional[bool] = False
    _internal_type: str = 'TextField'
    _header: typing.Optional[bytes] = b'JDDjangoEncryptedField'
    _key: typing.Optional[bytes] = None

    def __init__(self,
                 header: typing.Optional[bytes] = None,
                 algorithm: typing.Optional[str] = ALGORITHM_CHACHA20_POLY1305,
                 hide_algorithm: typing.Optional[bool] = False,
                 key: typing.Optional[bytes] = None,
                 *args, **kwargs):
        """
        __init__ function to set the field. The only relevant parameter here
        is header (see the definition before).

        This field cannot be primary_key, nor unique, nor db_index, so if set
        to a True value, will raise an Exception.

        :param header: optional. The initiation header for the algorithm.
        :param algorithm: optional. The encryption algorithm to use.
        :param hide_algorithm: optional. Hide algorithm details in the database.
        :param key: optional. A custom encryption key (bytes). If provided,
        this key will be used instead of settings.DJANGO_ENCRYPTED_FIELD_KEY.
        :param args: variable arguments.
        :param kwargs: variable arguments in a dictionary.
        """
        # If header is passed
        if header:
            self._header = header

        # The encryption algorithm to use. By default: ALGORITHM_CHACHA20_POLY1305
        if algorithm != self._algorithm:
            if algorithm in ALLOWED_ENCRYPTION_ALGORITHMS:
                self._algorithm = algorithm
            else:
                if settings.DEBUG is True:
                    logger.error(
                        "%s does not support this algorithm [%s]." % (self.__class__.__name__,
                                                                      str(algorithm))
                    )
                raise ImproperlyConfigured(
                    "%s does not support this algorithm [%s]."
                    % (self.__class__.__name__, str(algorithm))
                )

        # If we want to store only data, not the encryption algorithm details.
        if hide_algorithm is True:
            self._hide_algorithm = True

        # Custom key for this field instance.
        if key is not None:
            if isinstance(key, (bytes, bytearray)) is not True:
                raise InvalidKeyFormatException(
                    '%s: key must be bytes.' % self.__class__.__name__
                )
            self._key = key

        # Note: primary_key must not be set to True in anyway. This field
        # is not viable for this purpose.
        primary_key = kwargs.get('primary_key', False)
        if primary_key:
            if settings.DEBUG is True:
                logger.error(
                    "%s does not support primary_key different from False (or None)." % self.__class__.__name__
                )
            raise ImproperlyConfigured(
                "%s does not support primary_key different from False (or None)." % self.__class__.__name__
            )

        # Note: unique must not be set to True in anyway. This field
        # is not viable for this purpose.
        unique = kwargs.get('unique', False)
        if unique:
            if settings.DEBUG is True:
                logger.error(
                    "%s does not support unique different from False (or None)." % self.__class__.__name__
                )
            raise ImproperlyConfigured(
                "%s does not support unique different from False (or None)." % self.__class__.__name__
            )

        # Note: db_index must not be set to True in anyway. This field
        # is not viable for this purpose.
        db_index = kwargs.get('db_index', False)
        if db_index is True:
            if settings.DEBUG is True:
                logger.error(
                    "%s does not support db_index different from False (or None)." % self.__class__.__name__
                )
            raise ImproperlyConfigured(
                "%s does not support db_index different from False (or None)." % self.__class__.__name__
            )

        super().__init__(*args, **kwargs)

    def deconstruct(self) -> typing.Tuple[str, str, list, dict]:
        """
        Return enough information to recreate this field for migrations.
        The key is intentionally excluded for security — it should never
        be stored in migration files.
        """
        name, path, args, kwargs = super().deconstruct()
        if self._header != b'JDDjangoEncryptedField':
            kwargs['header'] = self._header
        if self._algorithm != ALGORITHM_CHACHA20_POLY1305:
            kwargs['algorithm'] = self._algorithm
        if self._hide_algorithm is True:
            kwargs['hide_algorithm'] = self._hide_algorithm
        return name, path, args, kwargs

    def _resolve_key(self, key: typing.Optional[bytes] = None) -> bytes:
        """
        Resolve the encryption key using the priority order:
        1. Explicitly passed key parameter
        2. Field-level key (self._key)
        3. Global settings.DJANGO_ENCRYPTED_FIELD_KEY

        :param key: optional explicit key override.
        :return: the resolved key as bytes.
        :raises MissingKeyException: if no key can be found.
        :raises InvalidKeyFormatException: if the key is not bytes.
        """
        resolved_key = key

        if resolved_key is None:
            resolved_key = self._key

        if resolved_key is None:
            try:
                resolved_key = settings.DJANGO_ENCRYPTED_FIELD_KEY
            except AttributeError:
                if settings.DEBUG is True:
                    logger.error(
                        'encrypted-field: no key found. Provide a key via the field, '
                        'the model instance, or settings.DJANGO_ENCRYPTED_FIELD_KEY.'
                    )
                raise MissingKeyException(
                    'encrypted-field: no key found. Provide a key via the field, '
                    'the model instance, or settings.DJANGO_ENCRYPTED_FIELD_KEY.'
                )

        if isinstance(resolved_key, (bytes, bytearray)) is not True:
            if settings.DEBUG is True:
                logger.error('encrypt/decrypt: key must be BYTES.')
            raise InvalidKeyFormatException('encrypt/decrypt: key must be BYTES.')

        return resolved_key

    def encrypt(self, data: str, key: typing.Optional[bytes] = None) -> str:
        """
        The encryption function. We opted for a simpler approach, letting the
        user pass a standard string, instead of requiring "bytes" or similar.

        All the required details will be within the object. Depending on the
        algorithm in self._algorithm, we will choose a particular encryption
        algorithm (valid in ALLOWED_ENCRYPTION_ALGORITHMS). By default the
        ChaCha20 Poly1305 algorithm will be used (best option for most of the
        scenarios and needs).

        :param data: the data we want to encrypt, as string.
        :param key: optional. A custom key to use for this encryption.
        If not provided, falls back to field-level key, then settings key.
        :return: will return a string including all the required elements and
        the encrypted string in a dictionary.
        """
        resolved_key = self._resolve_key(key)

        if self._algorithm == ALGORITHM_CHACHA20_POLY1305:
            return encrypt_chacha20_poly(data=data,
                                         header=self._header,
                                         key=resolved_key,
                                         hide_algorithm=self._hide_algorithm)
        elif self._algorithm == ALGORITHM_CHACHA20:
            return encrypt_chacha20(data=data,
                                    key=resolved_key,
                                    hide_algorithm=self._hide_algorithm)
        elif self._algorithm == ALGORITHM_SALSA20:
            return encrypt_salsa20(data=data,
                                   key=resolved_key,
                                   hide_algorithm=self._hide_algorithm)
        elif self._algorithm in ALGORITHM_AES_ALGORITHMS:
            return encrypt_aes(data=data,
                               header=self._header,
                               key=resolved_key,
                               algorithm=self._algorithm,
                               hide_algorithm=self._hide_algorithm)

        if settings.DEBUG is True:
            logger.info('encrypted-field: unknown algorithm when calling encrypt: [%s].' % str(self._algorithm))
        raise UnknownAlgorithmException(
            'encrypted-field: unknown algorithm when calling encrypt: [%s].' % str(self._algorithm)
        )

    def decrypt(self, encrypted_data: str, key: typing.Optional[bytes] = None) -> str:
        """
        The decryption function. We opted for a simpler approach, passing
        the encrypted data as string. Then conversion to bytes will be
        performed in the specific functions to be able to operate.

        :param encrypted_data: the encrypted data we want to decrypt.
        :param key: optional. A custom key to use for this decryption.
        If not provided, falls back to field-level key, then settings key.
        :return: will return a string with the decrypted data.
        """
        data_b64_fields = None
        algorithm = None

        resolved_key = self._resolve_key(key)

        try:
            data_b64_fields = json.loads(encrypted_data)
        except Exception as e:
            if settings.DEBUG is True:
                logger.error(
                    'encrypted_field.decrypt: encrypted_data doest not loads as JSON/Dict.'
                )
                logger.error('encrypted_field.decrypt: exception [%s]' % str(e))
                return None

        if 'algorithm' in data_b64_fields.keys():
            algorithm = data_b64_fields.get('algorithm', None)

        if not algorithm:
            try:
                algorithm = settings.DJANGO_ENCRYPTED_FIELD_ALGORITHM
            except AttributeError:
                if settings.DEBUG is True:
                    logger.error(
                        'encrypted_field.decrypt: algorithm UNKNOWN.'
                    )
                raise UnknownAlgorithmException('encrypted_field.decrypt: algorithm UNKNOWN.')

        data_b64_fields['algorithm'] = algorithm
        if algorithm == ALGORITHM_CHACHA20_POLY1305:
            return decrypt_chacha20_poly(encrypted_data=data_b64_fields, key=resolved_key)
        elif algorithm == ALGORITHM_CHACHA20:
            return decrypt_chacha20(encrypted_data=data_b64_fields, key=resolved_key)
        elif algorithm == ALGORITHM_SALSA20:
            return decrypt_salsa20(encrypted_data=data_b64_fields, key=resolved_key)
        elif algorithm in ALGORITHM_AES_ALGORITHMS:
            return decrypt_aes(encrypted_data=data_b64_fields, key=resolved_key)

        if settings.DEBUG is True:
            logger.error(
                'encrypted_field.decrypt: unsupported algorithm [%s]' % str(algorithm)
            )
        raise UnknownAlgorithmException('encrypted_field.decrypt: unsupported algorithm [%s]' % str(algorithm))

    ##########################################################################
    # We need the following functions as intermediaries to the Django ORM/DB
    # and from the database to the ORM -> objects.
    ##########################################################################
    def get_internal_type(self) -> str:
        return self._internal_type

    def pre_save(self, model_instance, add) -> typing.Optional[str]:
        """
        Called before saving. Encrypts the field value, using a per-instance
        key (model_instance._encryption_key) if available, otherwise falling
        back to the field-level key or global settings key.

        :param model_instance: the model instance being saved.
        :param add: True if the instance is being added (INSERT), False for UPDATE.
        :return: the encrypted value, or None if the value is empty.
        """
        value = getattr(model_instance, self.attname)
        if value == "" or value is None:
            return None

        instance_key = getattr(model_instance, '_encryption_key', None)
        encrypted_value = self.encrypt(value, key=instance_key)
        setattr(model_instance, self.attname, encrypted_value)
        return encrypted_value

    def from_db_value(self, value, expression, connection, *args) -> typing.Optional[str]:
        """
        Called when data is loaded from the database. Decrypts using the
        field-level key or global settings key.

        Note: per-instance keys are not available during from_db_value.
        For data encrypted with a per-instance key, use field.decrypt()
        manually with the appropriate key.

        :param value: the raw value from the database.
        :param expression: the expression used to fetch the value.
        :param connection: the database connection.
        :return: the decrypted value, or None if the value is empty.
        """
        if value == "" or value is None:
            return None

        return self.to_python(self.decrypt(encrypted_data=value))
