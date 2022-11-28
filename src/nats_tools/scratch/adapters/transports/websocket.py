# Copyright 2022 The NATS Authors
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import asyncio
import ssl
from typing import TYPE_CHECKING, List, Optional, Union
from urllib.parse import ParseResult

from ...interfaces.transport import Transport

if TYPE_CHECKING:
    import aiohttp
else:
    try:
        import aiohttp
    except ImportError:
        aiohttp = None


class WebSocketTransport(Transport):
    def __init__(self) -> None:
        if not aiohttp:
            raise ImportError(
                "Could not import aiohttp transport, please install it with `pip install aiohttp`"
            )
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._client: Optional[aiohttp.ClientSession] = None
        self._pending: Optional[asyncio.Queue[bytes]] = None
        self._close_task: Optional[asyncio.Future[bool]] = None

    async def connect(
        self,
        uri: ParseResult,
        buffer_size: int,
        connect_timeout: Optional[float] = None,
    ) -> None:
        """
        Connects to a server using websocket protocol through an aiohttp.ClientSession.
        The uri passed is of type ParseResult that can be obtained calling urllib.parse.urlparse.
        """
        self._pending = asyncio.Queue()
        self._client = aiohttp.ClientSession()
        self._close_task = asyncio.Future()
        # for websocket library, the uri must contain the scheme already
        self._ws = await self._client.ws_connect(
            uri.geturl(), timeout=connect_timeout or 10
        )

    async def connect_tls(
        self,
        uri: Union[str, ParseResult],
        ssl_context: ssl.SSLContext,
        buffer_size: int,
        connect_timeout: Optional[float] = None,
    ) -> None:
        """
        connect_tls is similar to connect except it tries to connect to a secure endpoint, using the provided ssl
        context. The uri can be provided as string in case the hostname differs from the uri hostname, in case it
        was provided as 'tls_hostname' on the options.
        """
        self._pending = asyncio.Queue()
        self._client = aiohttp.ClientSession()
        self._close_task = asyncio.Future()
        # for websocket library, the uri must contain the scheme already
        self._ws = await self._client.ws_connect(
            uri if isinstance(uri, str) else uri.geturl(),
            ssl=ssl_context,
            timeout=connect_timeout or 10,
        )

    def write(self, payload: bytes) -> None:
        """
        Write bytes to an asyncio.Queue.
        Needs a call to drain() to be successfully written.
        """
        assert self._pending is not None, "connect or connect_tls must be called first"
        self._pending.put_nowait(payload)

    def writelines(self, payload: List[bytes]) -> None:
        """
        Writes a list of bytes, item by item, to an asyncio.StreamWrite.
        Needs a call to drain() to be successfully written.
        """
        for message in payload:
            self.write(message)

    async def read(self, buffer_size: int) -> bytes:
        """
        Read bytes from websocket client session.
        buffer_size argument is ignored, as client always return a whole frame.
        """
        return await self.readline()

    async def readline(self) -> bytes:
        """
        Reads one whole frame of bytes (or message) from a websocket client session.
        """
        assert self._ws is not None, "connect or connect_tls must be called first"
        data = await self._ws.receive()
        return data.data  # type: ignore[no-any-return]

    async def drain(self) -> None:
        """
        Flushes the bytes queued for transmission when calling write() and writelines().
        """
        assert self._ws is not None, "connect or connect_tls must be called first"
        assert self._pending is not None, "connect or connect_tls must be called first"
        # send all the messages pending
        while not self._pending.empty():
            message = self._pending.get_nowait()
            await self._ws.send_bytes(message)

    async def wait_closed(self) -> None:
        """
        Request close and wait until the underlying websocket client session
        is successfully closed.
        """
        assert self._client is not None, "connect or connect_tls must be called first"
        assert (
            self._close_task is not None
        ), "connect or connect_tls must be called first"
        await self._close_task
        await self._client.close()
        self._ws = self._client = None

    def close(self) -> None:
        """
        Closes the websocket client session.
        """
        assert self._ws is not None, "connect or connect_tls must be called first"
        assert (
            self._close_task is not None
        ), "connect or connect_tls must be called first"
        self._close_task = asyncio.create_task(self._ws.close())

    def at_eof(self) -> bool:
        """
        Returns if underlying transport is at eof.
        """
        assert self._ws is not None, "connect or connect_tls must be called first"
        return self._ws._reader.at_eof()

    def __bool__(self) -> bool:
        """
        Returns if a websocket client has been initialized, either by calling connect of connect_tls.
        """
        return bool(self._ws)
