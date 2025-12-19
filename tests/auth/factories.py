import uuid
from datetime import datetime, timedelta, timezone

import factory
from faker import Faker

from src.core.uuid import uuid7
from src.user.models import EmailVerificationCode, PasswordResetCode

fake = Faker()


def _code_value() -> str:
    return f"{fake.random_number(digits=6, fix_len=True):06d}"


class EmailVerificationCodeFactory(factory.Factory):
    class Meta:
        model = EmailVerificationCode

    id = factory.LazyFunction(uuid7)
    user = None
    user_id = factory.LazyAttribute(
        lambda obj: obj.user.id if obj.user else uuid.uuid4()
    )
    raw_code = factory.LazyFunction(_code_value)
    expires_at = factory.LazyFunction(
        lambda: datetime.now(timezone.utc) + timedelta(minutes=30)
    )
    consumed_at = None

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        raw_code = kwargs.pop("raw_code", None) or _code_value()
        code = kwargs.pop("code", None) or raw_code
        obj = model_class(*args, code=code, **kwargs)
        obj.raw_code = raw_code
        return obj


class PasswordResetCodeFactory(factory.Factory):
    class Meta:
        model = PasswordResetCode

    id = factory.LazyFunction(uuid7)
    user = None
    user_id = factory.LazyAttribute(
        lambda obj: obj.user.id if obj.user else uuid.uuid4()
    )
    raw_code = factory.LazyFunction(_code_value)
    expires_at = factory.LazyFunction(
        lambda: datetime.now(timezone.utc) + timedelta(minutes=30)
    )
    consumed_at = None

    @classmethod
    def _create(cls, model_class, *args, **kwargs):
        raw_code = kwargs.pop("raw_code", None) or _code_value()
        code = kwargs.pop("code", None) or raw_code
        obj = model_class(*args, code=code, **kwargs)
        obj.raw_code = raw_code
        return obj
