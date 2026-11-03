"""Signed, expiring tokens for e-mail links (verification and password reset)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from itsdangerous import BadSignature, URLSafeTimedSerializer

from kalkan.web.models import User

EMAIL_TOKEN_MAX_AGE = 3 * 24 * 3600
RESET_TOKEN_MAX_AGE = 60 * 60


def password_fingerprint(password_hash: str) -> str:
    """Changes whenever the password changes, which makes reset links single-use."""
    return hashlib.sha256(password_hash.encode()).hexdigest()[:16]


@dataclass(frozen=True, slots=True)
class TokenClaims:
    user_id: int
    check: str  # e-mail address or password fingerprint


class Signer:
    def __init__(self, secret: str) -> None:
        self._serializer = URLSafeTimedSerializer(secret)

    def _dump(self, user_id: int, check: str, salt: str) -> str:
        return self._serializer.dumps({"u": user_id, "c": check}, salt=salt)

    def _load(self, token: str, salt: str, max_age: int) -> TokenClaims | None:
        try:
            data = self._serializer.loads(token, salt=salt, max_age=max_age)
        except BadSignature:  # also covers SignatureExpired
            return None
        if not isinstance(data, dict) or not isinstance(data.get("u"), int):
            return None
        return TokenClaims(data["u"], str(data.get("c", "")))

    def email_token(self, user: User) -> str:
        return self._dump(user.id, user.email, "email-verification")

    def read_email_token(
        self, token: str, max_age: int = EMAIL_TOKEN_MAX_AGE
    ) -> TokenClaims | None:
        return self._load(token, "email-verification", max_age)

    def reset_token(self, user: User) -> str:
        return self._dump(user.id, password_fingerprint(user.password_hash), "password-reset")

    def read_reset_token(
        self, token: str, max_age: int = RESET_TOKEN_MAX_AGE
    ) -> TokenClaims | None:
        return self._load(token, "password-reset", max_age)
