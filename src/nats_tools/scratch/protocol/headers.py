import typing as t
from email.parser import Parser
from io import StringIO

from .constants import _CRLF_, _SPC_, CRLF_SIZE, HEADERS_PREFIX, HEADERS_PREFIX_SIZE


class Headers(t.Mapping[str, str]):
    """
    An immutable, case-insensitive multidict.
    """

    def __init__(
        self,
        headers: t.Optional[t.Mapping[str, str]] = None,
        raw: t.Optional[t.List[t.Tuple[bytes, bytes]]] = None,
    ) -> None:
        self._list: t.List[t.Tuple[bytes, bytes]] = []
        if headers is not None:
            assert raw is None, 'Cannot set both "headers" and "raw".'
            self._list = [
                (
                    key.lower().encode("latin-1"),
                    value.encode("latin-1"),
                )
                for key, value in headers.items()
            ]
        elif raw is not None:
            self._list = [(raw_key.lower(), raw_value) for raw_key, raw_value in raw]

    @property
    def raw(self) -> t.List[t.Tuple[bytes, bytes]]:
        return list(self._list)

    def keys(self) -> t.List[str]:  # type: ignore[override]
        return [key.decode("latin-1") for key, value in self._list]

    def values(self) -> t.List[str]:  # type: ignore[override]
        return [value.decode("latin-1") for key, value in self._list]

    def items(self) -> t.List[t.Tuple[str, str]]:  # type: ignore[override]
        return [
            (key.decode("latin-1"), value.decode("latin-1"))
            for key, value in self._list
        ]

    def getlist(self, key: str) -> t.List[str]:
        get_header_key = key.lower().encode("latin-1")
        return [
            item_value.decode("latin-1")
            for item_key, item_value in self._list
            if item_key == get_header_key
        ]

    def mutablecopy(self) -> "MutableHeaders":
        return MutableHeaders(raw=self._list[:])

    def __getitem__(self, key: str) -> str:
        get_header_key = key.lower().encode("latin-1")
        for header_key, header_value in self._list:
            if header_key == get_header_key:
                return header_value.decode("latin-1")
        raise KeyError(key)

    def __contains__(self, key: t.Any) -> bool:
        get_header_key = key.lower().encode("latin-1")
        for header_key, header_value in self._list:
            if header_key == get_header_key:
                return True
        return False

    def __iter__(self) -> t.Iterator[t.Any]:
        return iter(self.keys())

    def __len__(self) -> int:
        return len(self._list)

    def __eq__(self, other: t.Any) -> bool:
        if not isinstance(other, Headers):
            return False
        return sorted(self._list) == sorted(other._list)

    def __repr__(self) -> str:
        class_name = self.__class__.__name__
        as_dict = dict(self.items())
        if len(as_dict) == len(self):
            return f"{class_name}({as_dict!r})"
        return f"{class_name}(raw={self.raw!r})"

    @classmethod
    def decode(cls, headers: bytes) -> "Headers":
        status_headers: t.List[t.Tuple[bytes, bytes]] = []
        # Check if header contains status
        first_line = headers.split(_CRLF_.encode(), maxsplit=1)[0]
        # Special case
        if first_line != HEADERS_PREFIX.encode():
            # Parse status and description
            status_infos = first_line[HEADERS_PREFIX_SIZE + 1 :]
            status, description = status_infos.split(sep=_SPC_.encode(), maxsplit=1)
            status_headers.append((b"status", status.strip()))
            status_headers.append((b"description", description.strip()))
        # Remove first line
        headers = headers[len(first_line) + CRLF_SIZE :]
        # Parse items
        raw_headers = StringIO(headers.decode())
        raw_headers.seek(0)
        key_values = [
            (k.encode("latin-1"), v.encode("latin-1"))
            for k, v in Parser().parse(raw_headers).items()
        ]
        # Finally present headers
        return Headers(raw=status_headers + key_values)

    def encode(self) -> bytes:
        hdr = bytearray()
        hdr.extend(HEADERS_PREFIX.encode())
        hdr.extend(_CRLF_.encode())
        for k, v in self.items():
            key = k.strip()
            if not key:
                # Skip empty keys
                continue
            hdr.extend(key.encode("latin-1"))
            hdr.extend(b": ")
            value = v.strip()
            hdr.extend(value.encode("latin-1"))
            hdr.extend(_CRLF_.encode())
        hdr.extend(_CRLF_.encode())
        return hdr


class MutableHeaders(Headers):
    def __setitem__(self, key: str, value: str) -> None:
        """
        Set the header `key` to `value`, removing any duplicate entries.
        Retains insertion order.
        """
        set_key = key.lower().encode("latin-1")
        set_value = value.encode("latin-1")

        found_indexes: "t.List[int]" = []
        for idx, (item_key, item_value) in enumerate(self._list):
            if item_key == set_key:
                found_indexes.append(idx)

        for idx in reversed(found_indexes[1:]):
            del self._list[idx]

        if found_indexes:
            idx = found_indexes[0]
            self._list[idx] = (set_key, set_value)
        else:
            self._list.append((set_key, set_value))

    def __delitem__(self, key: str) -> None:
        """
        Remove the header `key`.
        """
        del_key = key.lower().encode("latin-1")

        pop_indexes: "t.List[int]" = []
        for idx, (item_key, item_value) in enumerate(self._list):
            if item_key == del_key:
                pop_indexes.append(idx)

        for idx in reversed(pop_indexes):
            del self._list[idx]

    def __ior__(self, other: t.Mapping[str, str]) -> "MutableHeaders":
        if not isinstance(other, t.Mapping):
            raise TypeError(f"Expected a mapping but got {other.__class__.__name__}")
        self.update(other)
        return self

    def __or__(self, other: t.Mapping[str, str]) -> "MutableHeaders":
        if not isinstance(other, t.Mapping):
            raise TypeError(f"Expected a mapping but got {other.__class__.__name__}")
        new = self.mutablecopy()
        new.update(other)
        return new

    @property
    def raw(self) -> t.List[t.Tuple[bytes, bytes]]:
        return self._list

    def setdefault(self, key: str, value: str) -> str:
        """
        If the header `key` does not exist, then set it to `value`.
        Returns the header value.
        """
        set_key = key.lower().encode("latin-1")
        set_value = value.encode("latin-1")

        for idx, (item_key, item_value) in enumerate(self._list):
            if item_key == set_key:
                return item_value.decode("latin-1")
        self._list.append((set_key, set_value))
        return value

    def update(self, other: t.Mapping[str, str]) -> None:
        for key, val in other.items():
            self[key] = val

    def append(self, key: str, value: str) -> None:
        """
        Append a header, preserving any duplicate entries.
        """
        append_key = key.lower().encode("latin-1")
        append_value = value.encode("latin-1")
        self._list.append((append_key, append_value))
