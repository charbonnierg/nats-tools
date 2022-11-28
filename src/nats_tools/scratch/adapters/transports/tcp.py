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
from typing import List, Optional, Union
from urllib.parse import ParseResult

from ...interfaces.transport import Transport


class TCPTransport(Transport):
    def __init__(self) -> None:
        self._bare_io_reader: Optional[asyncio.StreamReader] = None
        self._io_reader: Optional[asyncio.StreamReader] = None
        self._bare_io_writer: Optional[asyncio.StreamWriter] = None
        self._io_writer: Optional[asyncio.StreamWriter] = None

    async def connect(
        self,
        uri: ParseResult,
        buffer_size: int,
        connect_timeout: Optional[float] = None,
    ) -> None:
        """
        Connect to a server using the asyncio.open_connection.
        The uri passed is of type ParseResult that can be
        obtained calling urllib.parse.urlparse.
        asyncio.open_connection creates an asyncio.StreamReader
        and an asyncio.StreamWriter which are stored as private
        attributes.
        """
        r, w = await asyncio.wait_for(
            asyncio.open_connection(
                host=uri.hostname,
                port=uri.port,
                limit=buffer_size,
            ),
            connect_timeout,
        )
        # We keep a reference to the initial transport we used when
        # establishing the connection in case we later upgrade to TLS
        # after getting the first INFO message. This is in order to
        # prevent the GC closing the socket after we send CONNECT
        # and replace the transport.
        #
        # See https://github.com/nats-io/asyncio-nats/issues/43
        self._bare_io_reader = self._io_reader = r
        self._bare_io_writer = self._io_writer = w

    async def connect_tls(
        self,
        uri: Union[str, ParseResult],
        ssl_context: ssl.SSLContext,
        buffer_size: int,
        connect_timeout: int,
    ) -> None:
        """
        Upgrade existing transport to TLS using asyncio.BaseEventLoop.start_tls.
        The uri can be provided as string in case the hostname differs from
        the uri hostname, in case it was provided as 'tls_hostname' on the options.
        """
        assert self._io_writer is not None, "connect must be called first"
        # manually recreate the stream reader/writer with a tls upgraded transport
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        transport_future = asyncio.get_running_loop().start_tls(
            self._io_writer.transport,
            protocol,
            ssl_context,
            # hostname here will be passed directly as string
            server_hostname=uri if isinstance(uri, str) else uri.hostname,
        )
        transport = await asyncio.wait_for(transport_future, connect_timeout)
        writer = asyncio.StreamWriter(
            transport, protocol, reader, asyncio.get_running_loop()  # type: ignore[arg-type]
        )
        self._io_reader, self._io_writer = reader, writer

    def write(self, payload: bytes) -> None:
        """
        Write bytes to an asyncio.StreamWriter.
        Needs a call to drain() to be successfully written.
        """
        assert self._io_writer is not None, "connect must be called first"
        self._io_writer.write(payload)

    def writelines(self, payload: List[bytes]) -> None:
        """
        Writes a list of bytes, item by item, to an asyncio.StreamWrite.
        Needs a call to drain() to be successfully written.
        """
        assert self._io_writer is not None, "connect must be called first"
        self._io_writer.writelines(payload)

    async def read(self, buffer_size: int) -> bytes:
        """
        Reads a sequence of bytes from an asyncio.StreamReader, up to buffer_size.
        """
        assert self._io_reader is not None, "connect must be called first"
        return await self._io_reader.read(buffer_size)

    async def readline(self) -> bytes:
        """
        Reads one whole frame of bytes (or message) from an asyncio.StreamReader.
        """
        assert self._io_reader is not None, "connect must be called first"
        return await self._io_reader.readline()

    async def drain(self) -> None:
        """
        Flushes the bytes queued for transmission when calling write() and writelines().
        """
        assert self._io_writer is not None, "connect must be called first"
        return await self._io_writer.drain()

    async def wait_closed(self) -> None:
        """
        Waits until the underlying asyncio.StreamWriter is successfully closed.
        """
        assert self._io_writer is not None, "connect must be called first"
        return await self._io_writer.wait_closed()

    def close(self) -> None:
        """
        Closes the asyncio.StreamWriter and underlying TCP connection.
        """
        assert self._io_writer is not None, "connect must be called first"
        return self._io_writer.close()

    def at_eof(self) -> bool:
        """
        Returns if underlying transport is at eof.
        """
        assert self._io_reader is not None, "connect must be called first"
        return self._io_reader.at_eof()

    def __bool__(self) -> bool:
        """
        Returns if the transport was initialized, either by calling connect of connect_tls.
        """
        return bool(self._io_writer) and bool(self._io_reader)

    def __aiter__(self) -> "TCPTransport":
        return self

    async def __anext__(self) -> bytes:
        return await self.readline()
