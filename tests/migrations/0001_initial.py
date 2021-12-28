from django.db import migrations, models
import encrypted_field.fields
from encrypted_field.fields import (
    ALGORITHM_CHACHA20,
    ALGORITHM_SALSA20,
    ALGORITHM_AES_GCM,
    ALGORITHM_AES_SIV,
    ALGORITHM_AES_EAX,
    ALGORITHM_AES_CCM,
    ALGORITHM_AES_OCB
)


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='MyModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('seed', encrypted_field.fields.EncryptedField()),
            ],
        ),
        migrations.CreateModel(
            name='MyModel2',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('seed_hidden', encrypted_field.fields.EncryptedField(hide_algorithm=True)),
            ],
        ),
        migrations.CreateModel(
            name='MyModel3',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('seed', encrypted_field.fields.EncryptedField(header=b'Custom header', algorithm=ALGORITHM_CHACHA20)),
            ],
        ),
        migrations.CreateModel(
            name='MyModel4',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('seed', encrypted_field.fields.EncryptedField(algorithm=ALGORITHM_SALSA20)),
            ],
        ),
        migrations.CreateModel(
            name='MyModel5',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('seed', encrypted_field.fields.EncryptedField(algorithm=ALGORITHM_AES_GCM)),
            ],
        ),
        migrations.CreateModel(
            name='MyModel6',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('seed', encrypted_field.fields.EncryptedField(algorithm=ALGORITHM_AES_SIV)),
            ],
        ),
        migrations.CreateModel(
            name='MyModel7',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('seed', encrypted_field.fields.EncryptedField(algorithm=ALGORITHM_AES_EAX)),
            ],
        ),
        migrations.CreateModel(
            name='MyModel8',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('seed', encrypted_field.fields.EncryptedField(algorithm=ALGORITHM_AES_CCM)),
            ],
        ),
        migrations.CreateModel(
            name='MyModel9',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('seed', encrypted_field.fields.EncryptedField(algorithm=ALGORITHM_AES_OCB)),
            ],
        )
    ]
