import factory
from faker import Faker

from src.auth.utils import hash_password
from src.core.uuid import uuid7
from src.user.models import User

fake = Faker()


class UserFactory(factory.Factory):
    class Meta:
        model = User

    id = factory.LazyFunction(uuid7)
    email = factory.LazyAttribute(lambda _: fake.email().lower())
    username = factory.LazyAttribute(
        lambda _: f"{fake.user_name().lower()}_{fake.random_number(digits=4)}"
    )
    is_email_verified = True
    token_version = 0
    is_deleted = False
    plain_password = factory.LazyFunction(lambda: fake.password(length=10))

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        plain_password = kwargs.pop("plain_password", None)
        password_hash = kwargs.pop("password_hash", None)
        if plain_password is None and password_hash is None:
            plain_password = fake.password(length=10)
        if password_hash is None and plain_password is not None:
            password_hash = hash_password(plain_password)

        obj = model_class(
            *args,
            password_hash=password_hash,
            **kwargs,
        )
        obj.plain_password = plain_password
        return obj
