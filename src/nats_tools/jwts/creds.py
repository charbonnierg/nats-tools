import contextlib
from pathlib import Path
from tempfile import TemporaryDirectory
import typing as t

from nats_tools import nkeys

from .api import decode_user, encode
from .errors import InvalidAccessTypeError
from .types import Claims, OperatorClaims, ScopedUserClaims, AccountClaims, CredsType


class CredentialsFile:
    def __init__(self, path: t.Union[str, Path]) -> None:
        self.path = Path(path).expanduser().absolute()

    def get_posix_path(self) -> str:
        """Get POSIX path to the credentials file as a string."""
        return self.path.as_posix()

    def read(self) -> str:
        """Read credentials file into a string."""
        creds = self.path.read_text()
        if "BEGIN NATS USER JWT" not in creds:
            raise ValueError("Invalid credentials file")
        if "END NATS USER JWT" not in creds:
            raise ValueError("Invalid credentials file")
        if "BEGIN USER NKEY SEED" not in creds:
            raise ValueError("Invalid credentials file")
        if "BEGIN USER NKEY SEED" not in creds:
            raise ValueError("Invalid credentials file")
        return creds

    def read_token(self) -> str:
        """Read token from credential file into a string."""
        user_jwt: t.Optional[bytearray] = None
        with self.path.open("rb") as f:
            for line in f:
                if b"BEGIN NATS USER JWT" in line:
                    jwt_start_pos = f.tell()
                    try:
                        next(f)
                    except StopIteration:
                        raise ValueError("Invalid credentials file")
                    jwt_end_pos = f.tell()
                    jwt_size = jwt_end_pos - jwt_start_pos - 1
                    f.seek(jwt_start_pos)
                    user_jwt = bytearray(jwt_size)
                    f.readinto(user_jwt)
                    break
        if not user_jwt:
            raise ValueError("Invalid credentials file")
        return user_jwt.decode("utf-8")

    def read_seed(self) -> str:
        """Read seed from credential file into a string."""
        user_seed: t.Optional[bytearray] = None
        with self.path.open("rb", buffering=0) as f:
            for line in f:
                # Detect line where the NKEY would start and end,
                # then seek and read into a fixed bytearray that
                # can be wiped.
                if b"BEGIN USER NKEY SEED" in line:
                    nkey_start_pos = f.tell()
                    try:
                        next(f)
                    except StopIteration:
                        raise ValueError("Invalid credentials file")
                    nkey_end_pos = f.tell()
                    nkey_size = nkey_end_pos - nkey_start_pos - 1
                    f.seek(nkey_start_pos)
                    user_seed = bytearray(nkey_size)
                    f.readinto(user_seed)
                    break
        if not user_seed:
            raise ValueError("Invalid credentials file")
        return user_seed.decode("utf-8")

    def decode_token(
        self,
        account_public_key: t.Union[str, bytes, bytearray, None] = None,
        issuer_public_key: t.Union[str, bytes, bytearray, None] = None,
        user_public_key: t.Union[str, bytes, bytearray, None] = None,
        verify: bool = True,
    ) -> ScopedUserClaims:
        return decode_user(
            self.read_token(),
            account_public_key=account_public_key,
            issuer_public_key=issuer_public_key,
            user_public_key=user_public_key,
            verify=verify,
        )

    def decode_seed(self) -> nkeys.KeyPair:
        return nkeys.from_seed(self.read_seed())

    def wipe(self) -> None:
        """Wipe credentials"""
        self.path.unlink(missing_ok=True)


def generate_credentials(
    user_seed: t.Union[str, bytes, bytearray],
    user_jwt: t.Optional[str] = None,
    user_claims: t.Union[
        Claims, OperatorClaims, AccountClaims, ScopedUserClaims, None
    ] = None,
    account_seed: t.Union[None, str, bytes, bytearray] = None,
) -> str:
    if user_jwt is None:
        if user_claims is None or account_seed is None:
            raise nkeys.errors.CannotSignError(
                "Either user_jwt or both user_claims and account_seed must be provided"
            )
        else:
            if user_claims.nats.type != CredsType.USER:
                raise InvalidAccessTypeError()
            user_jwt = encode(user_claims, seed=account_seed)
    user_kp = nkeys.from_seed(user_seed)

    creds = f"""-----BEGIN NATS USER JWT-----
{user_jwt}
------END NATS USER JWT------

************************* IMPORTANT *************************
NKEY Seed printed below can be used to sign and prove identity.
NKEYs are sensitive and should be treated as secrets.

-----BEGIN USER NKEY SEED-----
{user_kp.seed.decode('utf-8')}
------END USER NKEY SEED------

*************************************************************"""
    return creds


@contextlib.contextmanager
def mount_credentials(
    user_creds: t.Union[str, bytes, bytearray, None] = None,
    user_seed: t.Union[str, bytes, bytearray, None] = None,
    user_jwt: t.Optional[str] = None,
    user_claims: t.Union[Claims, ScopedUserClaims, None] = None,
    account_seed: t.Union[None, str, bytes, bytearray] = None,
) -> t.Iterator[CredentialsFile]:
    """Mount credentials to a temporary file.

    Credential file is removed when context manager is exited.
    """
    if user_creds is None:
        if user_seed is None:
            raise ValueError("Either user_creds or user_seed must be provided")
        creds = generate_credentials(
            user_seed=user_seed,
            user_jwt=user_jwt,
            user_claims=user_claims,
            account_seed=account_seed,
        ).encode("utf-8")
    else:
        if user_creds is None:
            raise ValueError("Either user_creds or user_seed must be provided")
        creds = nkeys.encoding._to_bytes(user_creds)
    with TemporaryDirectory() as tmpdir:
        creds_path = Path(tmpdir).joinpath("creds")
        creds_path.write_bytes(creds)
        del creds
        yield CredentialsFile(creds_path)
