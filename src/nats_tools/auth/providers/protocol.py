import contextlib
from pathlib import Path
from tempfile import TemporaryDirectory
import typing as t
import abc

from nats_tools import jwts


class CredsProvider(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def get_seed(self) -> str:
        """Get user NKEY seed"""
        raise NotImplementedError

    @abc.abstractmethod
    def get_token(
        self,
        client_id: t.Optional[str] = None,
        scope: t.Optional[str] = None,
        verify: bool = True,
    ) -> str:
        """Get user JWT"""
        raise NotImplementedError

    def get_credentials(
        self,
        client_id: str,
        scope: t.Optional[str] = None,
        verify: bool = True,
    ) -> str:
        """Get NATS credentials (containing both NKEY seed and user JWT)"""
        return jwts.generate_credentials(
            user_seed=self.get_seed(),
            user_jwt=self.get_token(client_id=client_id, scope=scope, verify=verify),
        )

    @contextlib.contextmanager
    def mount_credentials(
        self, client_id: str, scope: t.Optional[str] = None, verify: bool = True
    ) -> t.Iterator[jwts.creds.CredentialsFile]:
        """Mount credentials in temporary file"""
        with TemporaryDirectory() as tmpdir:
            creds_path = Path(tmpdir).joinpath("creds")
            creds = self.get_credentials(
                client_id=client_id, scope=scope, verify=verify
            )
            creds_path.write_text(creds)
            del creds
            yield jwts.creds.CredentialsFile(creds_path)
