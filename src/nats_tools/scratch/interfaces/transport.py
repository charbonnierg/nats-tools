import abc
import ssl
from typing import List, Optional, Union
from urllib.parse import ParseResult


class Transport(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def connect(
        self, uri: ParseResult, buffer_size: int, connect_timeout: Optional[float]
    ) -> None:
        """
        Connects to a server using the implemented transport. The uri passed is of type ParseResult that can be
        obtained calling urllib.parse.urlparse.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def connect_tls(
        self,
        uri: Union[str, ParseResult],
        ssl_context: ssl.SSLContext,
        buffer_size: int,
        connect_timeout: int,
    ) -> None:
        """
        connect_tls is similar to connect except it tries to connect to a secure endpoint, using the provided ssl
        context. The uri can be provided as string in case the hostname differs from the uri hostname, in case it
        was provided as 'tls_hostname' on the options.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def write(self, payload: bytes) -> None:
        """
        Write bytes to underlying transport. Needs a call to drain() to be successfully written.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def writelines(self, payload: List[bytes]) -> None:
        """
        Writes a list of bytes, one by one, to the underlying transport. Needs a call to drain() to be successfully
        written.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def read(self, buffer_size: int) -> bytes:
        """
        Reads a sequence of bytes from the underlying transport, up to buffer_size. The buffer_size is ignored in case
        the transport carries already frames entire messages (i.e. websocket).
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def readline(self) -> bytes:
        """
        Reads one whole frame of bytes (or message) from the underlying transport.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def drain(self) -> None:
        """
        Flushes the bytes queued for transmission when calling write() and writelines().
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def wait_closed(self) -> None:
        """
        Waits until the connection is successfully closed.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def close(self) -> None:
        """
        Closes the underlying transport.
        """
        pass

    @abc.abstractmethod
    def at_eof(self) -> bool:
        """
        Returns if underlying transport is at eof.
        """
        pass

    @abc.abstractmethod
    def __bool__(self) -> bool:
        """
        Returns if the transport was initialized, either by calling connect of connect_tls.
        """
        pass

    def __aiter__(self) -> "Transport":
        return self

    async def __anext__(self) -> bytes:
        if self.at_eof():
            raise StopAsyncIteration
        return await self.readline()
