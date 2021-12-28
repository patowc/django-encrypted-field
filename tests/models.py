from django.db import models
from encrypted_field import EncryptedField
from encrypted_field.fields import (
    ALGORITHM_CHACHA20,
    ALGORITHM_SALSA20,
    ALGORITHM_AES_GCM,
    ALGORITHM_AES_SIV,
    ALGORITHM_AES_EAX,
    ALGORITHM_AES_CCM,
    ALGORITHM_AES_OCB
)


class MyModel(models.Model):
    seed = EncryptedField()


class MyModel2(models.Model):
    seed_hidden = EncryptedField(hide_algorithm=True)


class MyModel3(models.Model):
    seed = EncryptedField(header=b'Custom header', algorithm=ALGORITHM_CHACHA20)


class MyModel4(models.Model):
    seed = EncryptedField(algorithm=ALGORITHM_SALSA20)


class MyModel5(models.Model):
    seed = EncryptedField(algorithm=ALGORITHM_AES_GCM)


class MyModel6(models.Model):
    seed = EncryptedField(algorithm=ALGORITHM_AES_SIV)


class MyModel7(models.Model):
    seed = EncryptedField(algorithm=ALGORITHM_AES_EAX)


class MyModel8(models.Model):
    seed = EncryptedField(algorithm=ALGORITHM_AES_CCM)


class MyModel9(models.Model):
    seed = EncryptedField(algorithm=ALGORITHM_AES_OCB)
