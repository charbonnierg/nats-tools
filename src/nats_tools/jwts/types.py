import typing as t
from dataclasses import asdict, dataclass
from enum import Enum

from . import errors


class CredsType(str, Enum):
    OPERATOR = "operator"
    ACCOUNT = "account"
    USER = "user"
    ACTIVATION = "activation"


class ActivationType(str, Enum):
    STREAM = "stream"
    SERVICE = "service"


class ResponseType(str, Enum):
    SINGLETON = "Singleton"
    STREAM = "Stream"
    CHUNKED = "Chunked"


APIFieldType = t.TypeVar("APIFieldType", bound="APIType")


@dataclass
class APIType:
    def to_values(self) -> t.Dict[str, t.Any]:
        """Return dataclass as dictionnary after omitting None values"""
        return {key: value for key, value in asdict(self).items() if value is not None}

    @classmethod
    def from_values(
        cls: t.Type[APIFieldType], values: t.Union[APIFieldType, t.Mapping[str, t.Any]]
    ) -> APIFieldType:
        """Create new instance from optional values"""
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        return cls(
            **{key: value for key, value in dict_values.items() if value is not None}
        )


@dataclass
class NATSLimits(APIType):
    data: int
    payload: int
    subs: int


@dataclass
class PartialNATSLimits(APIType):
    data: t.Optional[int] = None
    payload: t.Optional[int] = None
    subs: t.Optional[int] = None


@dataclass
class AccountLimits(APIType):
    imports: int
    exports: int
    wildcards: bool
    conn: int
    leaf: int
    disallow_bearer: bool


@dataclass
class PartialAccountLimits(APIType):
    imports: t.Optional[int] = None
    exports: t.Optional[int] = None
    wildcards: t.Optional[bool] = None
    conn: t.Optional[int] = None
    leaf: t.Optional[int] = None
    disallow_bearer: t.Optional[bool] = None


@dataclass
class JetstreamLimits(APIType):
    mem_storage: int
    dist_storage: int
    streams: int
    consumer: int
    mem_max_stream_bytes: int
    dist_max_stream_bytes: int
    max_bytes_required: bool
    max_ack_pending: int


@dataclass
class PartialJetstreamLimits(APIType):
    mem_storage: t.Optional[int] = None
    dist_storage: t.Optional[int] = None
    streams: t.Optional[int] = None
    consumer: t.Optional[int] = None
    mem_max_stream_bytes: t.Optional[int] = None
    dist_max_stream_bytes: t.Optional[int] = None
    max_bytes_required: t.Optional[bool] = None
    max_ack_pending: t.Optional[int] = None


TieredLimitsT = t.TypeVar("TieredLimitsT", bound="TieredLimits")


@dataclass
class TieredLimits(APIType):
    R1: t.Optional[PartialJetstreamLimits] = None
    R3: t.Optional[PartialJetstreamLimits] = None

    @classmethod
    def from_values(
        cls: t.Type[TieredLimitsT],
        values: t.Union[TieredLimitsT, t.Mapping[str, t.Any]],
    ) -> TieredLimitsT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        r1 = dict_values.get("R1", None)
        if r1 is not None:
            r1 = PartialJetstreamLimits.from_values(r1)
        r3 = dict_values.get("R3", None)
        if r3 is not None:
            r3 = PartialJetstreamLimits.from_values(r3)
        return super().from_values({"R1": r1, "R3": r3})

    def to_values(self) -> t.Dict[str, t.Any]:
        values = {}
        if self.R1 is not None:
            values["R1"] = self.R1.to_values()
        if self.R3 is not None:
            values["R3"] = self.R3.to_values()
        return values


JetstreamTieredLimitsT = t.TypeVar(
    "JetstreamTieredLimitsT", bound="JetstreamTieredLimits"
)


@dataclass
class JetstreamTieredLimits(APIType):
    tiered_limits: t.Optional[TieredLimits] = None

    @classmethod
    def from_values(
        cls: t.Type[JetstreamTieredLimitsT],
        values: t.Union[JetstreamTieredLimitsT, t.Mapping[str, t.Any]],
    ) -> JetstreamTieredLimitsT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        tiered_limits = dict_values.get("tiered_limits", None)
        if tiered_limits is not None:
            dict_values = {
                **dict_values,
                "tiered_limits": TieredLimits.from_values(tiered_limits),
            }
        return super().from_values(dict_values)

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if self.tiered_limits is not None:
            values["tiered_limits"] = self.tiered_limits.to_values()
        return values


@dataclass
class OperatorLimits(
    PartialNATSLimits,
    PartialAccountLimits,
    PartialJetstreamLimits,
    JetstreamTieredLimits,
):
    pass


@dataclass
class ResponsePermissions(APIType):
    max: int
    ttl: int


@dataclass
class Permission(APIType):
    allow: t.Optional[t.List[str]] = None
    deny: t.Optional[t.List[str]] = None


PermissionsT = t.TypeVar("PermissionsT", bound="Permissions")


@dataclass
class Permissions(APIType):
    pub: t.Optional[Permission] = None
    sub: t.Optional[Permission] = None
    resp: t.Optional[ResponsePermissions] = None

    @classmethod
    def from_values(
        cls: t.Type[PermissionsT], values: t.Union[PermissionsT, t.Mapping[str, t.Any]]
    ) -> PermissionsT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        dict_values = {**dict_values}
        if "pub" in dict_values and dict_values["pub"] is not None:
            dict_values["pub"] = Permission.from_values(dict_values["pub"])
        if "sub" in dict_values and dict_values["sub"] is not None:
            dict_values["sub"] = Permission.from_values(dict_values["sub"])
        if "resp" in dict_values and dict_values["resp"] is not None:
            dict_values["resp"] = ResponsePermissions.from_values(dict_values["resp"])
        return super().from_values(dict_values)

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if self.pub is not None:
            values["pub"] = self.pub.to_values()
        else:
            values.pop("pub", None)
        if self.sub is not None:
            values["sub"] = self.sub.to_values()
        else:
            values.pop("sub", None)
        if self.resp is not None:
            values["resp"] = self.resp.to_values()
        else:
            values.pop("resp", None)
        return values


@dataclass
class TimeRange(APIType):
    start: t.Optional[str] = None
    end: t.Optional[str] = None


UserLimitsT = t.TypeVar("UserLimitsT", bound="UserLimits")


@dataclass
class UserLimits(APIType):
    src: t.Optional[t.List[str]] = None
    times: t.Optional[t.List[TimeRange]] = None
    locale: t.Optional[str] = None

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if self.times:
            values = {
                **values,
                "times": [
                    item.to_values() if isinstance(item, TimeRange) else item
                    for item in self.times
                ],
            }
        return values

    @classmethod
    def from_values(
        cls: t.Type[UserLimitsT], values: t.Union[UserLimitsT, t.Mapping[str, t.Any]]
    ) -> UserLimitsT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        if "times" in dict_values and dict_values["times"]:
            dict_values = {
                **dict_values,
                "times": [
                    TimeRange.from_values(timerange)
                    for timerange in dict_values["times"]
                ],
            }
        return super().from_values(dict_values)


@dataclass
class Limits(UserLimits, NATSLimits):
    pass


class ConnectionType(str, Enum):
    STANDARD = "STANDARD"
    WEBSOCKET = "WEBSOCKET"
    LEAFNODE = "LEAFNODE"
    LEAFNODE_WS = "LEAFNODE_WS"
    MQTT = "MQTT"
    MQTT_WS = "MQTT_WS"


UserPermissionsLimitsT = t.TypeVar(
    "UserPermissionsLimitsT", bound="UserPermissionsLimits"
)


@dataclass
class UserPermissionsLimits(Permissions, Limits):
    bearer_token: t.Optional[bool] = None
    allowed_connection_types: t.Optional[t.List[ConnectionType]] = None

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if self.allowed_connection_types:
            values["allowed_connection_types"] = [
                enum.value if isinstance(enum, ConnectionType) else enum
                for enum in self.allowed_connection_types
            ]
        return values

    @classmethod
    def from_values(
        cls: t.Type[UserPermissionsLimitsT],
        values: t.Union[UserPermissionsLimitsT, t.Mapping[str, t.Any]],
    ) -> UserPermissionsLimitsT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        if "allowed_connection_types" in dict_values:
            dict_values = {
                **dict_values,
                "allowed_connection_types": [
                    ConnectionType(value)
                    for value in dict_values["allowed_connection_types"]
                ],
            }
        return super().from_values(dict_values)


PartialUserPermissionsLimitsT = t.TypeVar(
    "PartialUserPermissionsLimitsT", bound="PartialUserPermissionsLimits"
)


@dataclass
class PartialUserPermissionsLimits(UserLimits, PartialNATSLimits):
    bearer_token: t.Optional[bool] = None
    allowed_connection_types: t.Optional[t.List[ConnectionType]] = None

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if self.allowed_connection_types:
            values["allowed_connection_types"] = [
                enum.value if isinstance(enum, ConnectionType) else enum
                for enum in self.allowed_connection_types
            ]
        return values

    @classmethod
    def from_values(
        cls: t.Type[PartialUserPermissionsLimitsT],
        values: t.Union[PartialUserPermissionsLimitsT, t.Mapping[str, t.Any]],
    ) -> PartialUserPermissionsLimitsT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        if "allowed_connection_types" in dict_values:
            dict_values = {
                **dict_values,
                "allowed_connection_types": [
                    ConnectionType(value)
                    for value in dict_values["allowed_connection_types"]
                ],
            }
        return super().from_values(dict_values)


@dataclass
class IssuerAccount(APIType):
    issuer_account: str


@dataclass
class User(UserPermissionsLimits, IssuerAccount):  # type: ignore[misc]
    pass


VersionTypeT = t.TypeVar("VersionTypeT", bound="VersionType")


@dataclass
class VersionType(APIType):
    version: int = 2
    type: t.Optional[CredsType] = None

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if isinstance(self.type, CredsType):
            values["type"] = self.type.value
        return values

    @classmethod
    def from_values(
        cls: t.Type[VersionTypeT], values: t.Union[VersionTypeT, t.Mapping[str, t.Any]]
    ) -> VersionTypeT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        if "type" in dict_values and dict_values["type"] is not None:
            dict_values = {**dict_values, "type": CredsType(dict_values["type"])}
        return super().from_values(dict_values)


ActivationFieldsT = t.TypeVar("ActivationFieldsT", bound="ActivationFields")


@dataclass
class ActivationFields(APIType):
    subject: str
    issuer_account: str
    kind: t.Optional[ActivationType] = None

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if isinstance(self.kind, ActivationType):
            values["kind"] = self.kind.value
        return values

    @classmethod
    def from_values(
        cls: t.Type[ActivationFieldsT],
        values: t.Union[ActivationFieldsT, t.Mapping[str, t.Any]],
    ) -> ActivationFieldsT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        if "kind" in dict_values and dict_values["kind"] is not None:
            dict_values = {**dict_values, "kind": ActivationType(dict_values["kind"])}
        return super().from_values(dict_values)


@dataclass
class Activation(VersionType, ActivationFields):  # type: ignore[misc]
    pass


ImportExportBaseT = t.TypeVar("ImportExportBaseT", bound="ImportExportBase")


@dataclass
class ImportExportBase(APIType):
    name: str
    subject: str
    type: ActivationType

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if isinstance(values["type"], ActivationType):
            values["type"] = values["type"].value
        return values

    @classmethod
    def from_values(
        cls: t.Type[ImportExportBaseT],
        values: t.Union[ImportExportBaseT, t.Mapping[str, t.Any]],
    ) -> ImportExportBaseT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        values = {**dict_values, "type": ActivationType(dict_values["type"])}
        return super().from_values(dict_values)


@dataclass
class ServiceLatency(APIType):
    sampling: str
    results: str


@dataclass
class Info(APIType):
    description: t.Optional[str] = None
    info_url: t.Optional[str] = None


@dataclass
class Import(ImportExportBase):
    account: str
    token: t.Optional[str] = None
    to: t.Optional[str] = None
    local_subject: t.Optional[str] = None
    share: t.Optional[bool] = None


ExportT = t.TypeVar("ExportT", bound="Export")


@dataclass
class Export(Info, ImportExportBase):
    token_req: t.Optional[str] = None
    revocations: t.Optional[t.Dict[str, int]] = None
    response_type: t.Optional[ResponseType] = None
    response_threshold: t.Optional[int] = None
    service_latency: t.Optional[ServiceLatency] = None
    account_token_position: t.Optional[int] = None

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if "response_type" in values and isinstance(
            values["response_type"], ResponseType
        ):
            values["response_type"] = values["response_type"].value
        if "service_latency" in values and isinstance(
            values["service_latency"], ServiceLatency
        ):
            values["service_latency"] = values["service_latency"].to_values()
        return values

    @classmethod
    def from_values(
        cls: t.Type[ExportT], values: t.Union[ExportT, t.Mapping[str, t.Any]]
    ) -> ExportT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        if "response_type" in dict_values:
            values = {
                **dict_values,
                "response_type": ResponseType(dict_values["response_type"]),
            }
        if (
            "service_latency" in dict_values
            and dict_values["service_latency"] is not None
        ):
            values = {
                **dict_values,
                "service_latency": ServiceLatency.from_values(
                    dict_values["service_latency"]
                ),
            }
        return super().from_values(values)


SigningKeyT = t.TypeVar("SigningKeyT", bound="SigningKey")


@dataclass
class SigningKey(APIType):
    kind: t.Literal["user_scope"]
    key: str
    role: str
    template: t.Optional[PartialUserPermissionsLimits] = None

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if isinstance(self.template, PartialUserPermissionsLimits):
            values["template"] = self.template.to_values()
        return values

    @classmethod
    def from_values(
        cls: t.Type[SigningKeyT], values: t.Union[SigningKeyT, t.Mapping[str, t.Any]]
    ) -> SigningKeyT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        if "template" in dict_values and dict_values["template"] is not None:
            dict_values = {
                **dict_values,
                "template": PartialUserPermissionsLimits.from_values(
                    dict_values["template"]
                ),
            }
        return super().from_values(dict_values)


@dataclass
class GenericFields(VersionType):
    tags: t.Optional[t.List[str]] = None


OperatorT = t.TypeVar("OperatorT", bound="Operator")


@dataclass
class Operator(GenericFields):
    signing_keys: t.Optional[t.List[t.Union[str, SigningKey]]] = None
    account_server_url: t.Optional[str] = None
    operator_service_urls: t.Optional[t.List[str]] = None
    system_account: t.Optional[str] = None

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if self.signing_keys:
            values["signing_keys"] = [
                key.to_values() if isinstance(key, SigningKey) else key
                for key in self.signing_keys
            ]
        return values

    @classmethod
    def from_values(
        cls: t.Type[OperatorT], values: t.Union[OperatorT, t.Mapping[str, t.Any]]
    ) -> OperatorT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        dict_values = {**dict_values}
        if "type" not in dict_values:
            dict_values["type"] = CredsType.OPERATOR
        else:
            dict_values["type"] = CredsType(dict_values["type"])
            if dict_values["type"] != CredsType.OPERATOR:
                raise errors.InvalidAccessTypeError()
        if "signing_keys" in dict_values and dict_values["signing_keys"]:
            dict_values = {
                **dict_values,
                "signing_keys": [
                    key if isinstance(key, str) else SigningKey.from_values(key)
                    for key in dict_values["signing_keys"]
                ],
            }
        return super().from_values(values)


AccountT = t.TypeVar("AccountT", bound="Account")


@dataclass
class Account(GenericFields, Info):
    imports: t.Optional[t.List[Import]] = None
    exports: t.Optional[t.List[Export]] = None
    limits: t.Optional[OperatorLimits] = None
    signing_keys: t.Optional[t.List[t.Union[str, SigningKey]]] = None
    revocations: t.Optional[t.Dict[str, int]] = None
    default_permissions: t.Optional[Permissions] = None
    disallow_bearer: t.Optional[bool] = None

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if self.imports:
            values["imports"] = [
                import_.to_values() if isinstance(import_, Import) else import_
                for import_ in self.imports
            ]
        if self.exports:
            values["exports"] = [
                export.to_values() if isinstance(export, Export) else export
                for export in self.exports
            ]
        if self.limits:
            values["limits"] = self.limits.to_values()
        if self.default_permissions:
            values["default_permissions"] = self.default_permissions.to_values()
        return values

    @classmethod
    def from_values(
        cls: t.Type[AccountT], values: t.Union[AccountT, t.Mapping[str, t.Any]]
    ) -> AccountT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        dict_values = {**dict_values}
        if "type" not in dict_values:
            dict_values["type"] = CredsType.ACCOUNT
        else:
            dict_values["type"] = CredsType(dict_values["type"])
            if dict_values["type"] != CredsType.ACCOUNT:
                raise errors.InvalidAccessTypeError()
        if "imports" in dict_values and dict_values["imports"] is not None:
            dict_values = {
                **dict_values,
                "imports": [
                    Import.from_values(value) for value in dict_values["imports"]
                ],
            }
        if "exports" in dict_values and dict_values["exports"] is not None:
            dict_values = {
                **dict_values,
                "exports": [
                    Export.from_values(value) for value in dict_values["exports"]
                ],
            }
        if "limits" in dict_values and dict_values["limits"] is not None:
            dict_values = {
                **dict_values,
                "limits": OperatorLimits.from_values(dict_values["limits"]),
            }
        if (
            "default_permissions" in dict_values
            and dict_values["default_permissions"] is not None
        ):
            dict_values = {
                **dict_values,
                "default_permissions": Permissions.from_values(
                    dict_values["default_permissions"]
                ),
            }
        return super().from_values(dict_values)


ScopedUserT = t.TypeVar("ScopedUserT", bound="ScopedUser")


@dataclass
class ScopedUser(GenericFields, UserPermissionsLimits):
    issuer_account: t.Optional[str] = None

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        if self.allowed_connection_types:
            values["allowed_connection_types"] = [
                conntype.value if isinstance(conntype, ConnectionType) else conntype
                for conntype in self.allowed_connection_types
            ]
        return values

    @classmethod
    def from_values(
        cls: t.Type[ScopedUserT], values: t.Union[ScopedUserT, t.Mapping[str, t.Any]]
    ) -> ScopedUserT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        dict_values = {**dict_values}
        if "type" not in dict_values:
            dict_values["type"] = CredsType.USER
        else:
            dict_values["type"] = CredsType(dict_values["type"])
            if dict_values["type"] != CredsType.USER:
                raise errors.InvalidAccessTypeError()
        if (
            "allowed_connection_types" in dict_values
            and dict_values["allowed_connection_types"] is not None
        ):
            dict_values = {
                **dict_values,
                "allowed_connection_types": [
                    ConnectionType(value)
                    for value in dict_values["allowed_connection_types"]
                ],
            }
        return super().from_values(dict_values)


@dataclass
class OptionalClaimsData(APIType):
    aud: t.Optional[str] = None
    exp: t.Optional[int] = None
    nbf: t.Optional[int] = None


ClaimsDataT = t.TypeVar("ClaimsDataT", bound="RequiredClaimsData")


@dataclass
class RequiredClaimsData(APIType):
    jti: str
    iat: int
    iss: str
    name: str
    sub: str
    nats: t.Union[Operator, Account, ScopedUser]

    def to_values(self) -> t.Dict[str, t.Any]:
        values = super().to_values()
        values["nats"] = self.nats.to_values()
        return values

    @classmethod
    def from_values(
        cls: t.Type[ClaimsDataT], values: t.Union[ClaimsDataT, t.Mapping[str, t.Any]]
    ) -> ClaimsDataT:
        if isinstance(values, cls):
            return values
        dict_values = t.cast(t.Mapping[str, t.Any], values)
        dict_values = {**dict_values}
        if "type" in dict_values:
            dict_values = {**dict_values, "type": CredsType(dict_values["type"])}
        if "nats" in dict_values:
            if "type" in dict_values["nats"]:
                creds_type = CredsType(dict_values["nats"]["type"])
                if creds_type == CredsType.OPERATOR:
                    dict_values = {
                        **dict_values,
                        "nats": Operator.from_values(dict_values["nats"]),
                    }
                elif creds_type == CredsType.ACCOUNT:
                    dict_values = {
                        **dict_values,
                        "nats": Account.from_values(dict_values["nats"]),
                    }
                elif creds_type == CredsType.USER:
                    dict_values = {
                        **dict_values,
                        "nats": ScopedUser.from_values(dict_values["nats"]),
                    }
                else:
                    raise TypeError(f"Invalid NATS access type: {creds_type}")
        return super().from_values(dict_values)


@dataclass
class Claims(OptionalClaimsData, RequiredClaimsData):
    pass


class RequiredOperatorClaimsData(RequiredClaimsData):
    nats: Operator


@dataclass
class OperatorClaims(OptionalClaimsData, RequiredOperatorClaimsData):
    pass


@dataclass
class RequiredAccountClaimsData(RequiredClaimsData):
    nats: Account


@dataclass
class AccountClaims(OptionalClaimsData, RequiredAccountClaimsData):
    pass


@dataclass
class RequiredScopedUserClaimsData(RequiredClaimsData):
    nats: ScopedUser


@dataclass
class ScopedUserClaims(OptionalClaimsData, RequiredScopedUserClaimsData):
    pass
