from dataclasses import dataclass, field


@dataclass
class SemverVersion:
    """Semver version"""

    value: str
    major_version: int = field(init=False)
    minor_version: int = field(init=False)
    patch_version: int = field(init=False)
    dev_version: str = field(init=False)

    def __post_init__(self) -> None:
        """Optimistically parse semver version from string"""
        v = (self.value).split("-")
        if len(v) > 1:
            self.dev_version = v[1]
        tokens = v[0].split(".")
        n = len(tokens)
        if n > 1:
            self.major_version = int(tokens[0])
        if n > 2:
            self.minor_version = int(tokens[1])
        if n > 3:
            self.patch_version = int(tokens[2])
