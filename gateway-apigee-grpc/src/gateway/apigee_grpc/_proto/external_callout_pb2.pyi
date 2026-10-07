from google.protobuf import descriptor_pb2 as _descriptor_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor
IMMUTABLE_FIELD_NUMBER: _ClassVar[int]
immutable: _descriptor.FieldDescriptor

class MessageContext(_message.Message):
    __slots__ = ("request", "response", "error", "fault", "api_proxy", "client", "current_flow", "message_id", "organization_name", "environment_name", "proxy", "route", "target", "additional_flow_variables")
    class AdditionalFlowVariablesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: FlowVariable
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[FlowVariable, _Mapping]] = ...) -> None: ...
    REQUEST_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    FAULT_FIELD_NUMBER: _ClassVar[int]
    API_PROXY_FIELD_NUMBER: _ClassVar[int]
    CLIENT_FIELD_NUMBER: _ClassVar[int]
    CURRENT_FLOW_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_ID_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_NAME_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_NAME_FIELD_NUMBER: _ClassVar[int]
    PROXY_FIELD_NUMBER: _ClassVar[int]
    ROUTE_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    ADDITIONAL_FLOW_VARIABLES_FIELD_NUMBER: _ClassVar[int]
    request: Request
    response: Response
    error: Error
    fault: Fault
    api_proxy: ApiProxy
    client: Client
    current_flow: CurrentFlow
    message_id: str
    organization_name: str
    environment_name: str
    proxy: Proxy
    route: Route
    target: Target
    additional_flow_variables: _containers.MessageMap[str, FlowVariable]
    def __init__(self, request: _Optional[_Union[Request, _Mapping]] = ..., response: _Optional[_Union[Response, _Mapping]] = ..., error: _Optional[_Union[Error, _Mapping]] = ..., fault: _Optional[_Union[Fault, _Mapping]] = ..., api_proxy: _Optional[_Union[ApiProxy, _Mapping]] = ..., client: _Optional[_Union[Client, _Mapping]] = ..., current_flow: _Optional[_Union[CurrentFlow, _Mapping]] = ..., message_id: _Optional[str] = ..., organization_name: _Optional[str] = ..., environment_name: _Optional[str] = ..., proxy: _Optional[_Union[Proxy, _Mapping]] = ..., route: _Optional[_Union[Route, _Mapping]] = ..., target: _Optional[_Union[Target, _Mapping]] = ..., additional_flow_variables: _Optional[_Mapping[str, FlowVariable]] = ...) -> None: ...

class Request(_message.Message):
    __slots__ = ("uri", "verb", "http_version", "headers", "form_params", "query_params", "content")
    class HeadersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: Strings
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[Strings, _Mapping]] = ...) -> None: ...
    class FormParamsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: Strings
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[Strings, _Mapping]] = ...) -> None: ...
    class QueryParamsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: Strings
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[Strings, _Mapping]] = ...) -> None: ...
    URI_FIELD_NUMBER: _ClassVar[int]
    VERB_FIELD_NUMBER: _ClassVar[int]
    HTTP_VERSION_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    FORM_PARAMS_FIELD_NUMBER: _ClassVar[int]
    QUERY_PARAMS_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    uri: str
    verb: str
    http_version: str
    headers: _containers.MessageMap[str, Strings]
    form_params: _containers.MessageMap[str, Strings]
    query_params: _containers.MessageMap[str, Strings]
    content: str
    def __init__(self, uri: _Optional[str] = ..., verb: _Optional[str] = ..., http_version: _Optional[str] = ..., headers: _Optional[_Mapping[str, Strings]] = ..., form_params: _Optional[_Mapping[str, Strings]] = ..., query_params: _Optional[_Mapping[str, Strings]] = ..., content: _Optional[str] = ...) -> None: ...

class Response(_message.Message):
    __slots__ = ("status_code", "reason_phrase", "headers", "content")
    class HeadersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: Strings
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[Strings, _Mapping]] = ...) -> None: ...
    STATUS_CODE_FIELD_NUMBER: _ClassVar[int]
    REASON_PHRASE_FIELD_NUMBER: _ClassVar[int]
    HEADERS_FIELD_NUMBER: _ClassVar[int]
    CONTENT_FIELD_NUMBER: _ClassVar[int]
    status_code: int
    reason_phrase: str
    headers: _containers.MessageMap[str, Strings]
    content: str
    def __init__(self, status_code: _Optional[int] = ..., reason_phrase: _Optional[str] = ..., headers: _Optional[_Mapping[str, Strings]] = ..., content: _Optional[str] = ...) -> None: ...

class Fault(_message.Message):
    __slots__ = ("name", "type", "category", "fault_string")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    CATEGORY_FIELD_NUMBER: _ClassVar[int]
    FAULT_STRING_FIELD_NUMBER: _ClassVar[int]
    name: str
    type: str
    category: str
    fault_string: str
    def __init__(self, name: _Optional[str] = ..., type: _Optional[str] = ..., category: _Optional[str] = ..., fault_string: _Optional[str] = ...) -> None: ...

class Error(_message.Message):
    __slots__ = ("message", "response")
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_FIELD_NUMBER: _ClassVar[int]
    message: str
    response: Response
    def __init__(self, message: _Optional[str] = ..., response: _Optional[_Union[Response, _Mapping]] = ...) -> None: ...

class Policy(_message.Message):
    __slots__ = ("name", "time_taken_ns", "properties")
    class PropertiesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: Strings
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[Strings, _Mapping]] = ...) -> None: ...
    NAME_FIELD_NUMBER: _ClassVar[int]
    TIME_TAKEN_NS_FIELD_NUMBER: _ClassVar[int]
    PROPERTIES_FIELD_NUMBER: _ClassVar[int]
    name: str
    time_taken_ns: int
    properties: _containers.MessageMap[str, Strings]
    def __init__(self, name: _Optional[str] = ..., time_taken_ns: _Optional[int] = ..., properties: _Optional[_Mapping[str, Strings]] = ...) -> None: ...

class ApiProxy(_message.Message):
    __slots__ = ("name", "revision")
    NAME_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    name: str
    revision: str
    def __init__(self, name: _Optional[str] = ..., revision: _Optional[str] = ...) -> None: ...

class Client(_message.Message):
    __slots__ = ("cn", "country", "email_address", "host", "ip", "locality", "organization", "organization_unit", "port", "scheme", "state", "ssl_enabled")
    CN_FIELD_NUMBER: _ClassVar[int]
    COUNTRY_FIELD_NUMBER: _ClassVar[int]
    EMAIL_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    IP_FIELD_NUMBER: _ClassVar[int]
    LOCALITY_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_UNIT_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    SCHEME_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    SSL_ENABLED_FIELD_NUMBER: _ClassVar[int]
    cn: str
    country: str
    email_address: str
    host: str
    ip: str
    locality: str
    organization: str
    organization_unit: str
    port: int
    scheme: str
    state: str
    ssl_enabled: bool
    def __init__(self, cn: _Optional[str] = ..., country: _Optional[str] = ..., email_address: _Optional[str] = ..., host: _Optional[str] = ..., ip: _Optional[str] = ..., locality: _Optional[str] = ..., organization: _Optional[str] = ..., organization_unit: _Optional[str] = ..., port: _Optional[int] = ..., scheme: _Optional[str] = ..., state: _Optional[str] = ..., ssl_enabled: _Optional[bool] = ...) -> None: ...

class CurrentFlow(_message.Message):
    __slots__ = ("name", "description")
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    name: str
    description: str
    def __init__(self, name: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class Proxy(_message.Message):
    __slots__ = ("endpoint_name", "client_ip", "base_path", "path_suffix", "url")
    ENDPOINT_NAME_FIELD_NUMBER: _ClassVar[int]
    CLIENT_IP_FIELD_NUMBER: _ClassVar[int]
    BASE_PATH_FIELD_NUMBER: _ClassVar[int]
    PATH_SUFFIX_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    endpoint_name: str
    client_ip: str
    base_path: str
    path_suffix: str
    url: str
    def __init__(self, endpoint_name: _Optional[str] = ..., client_ip: _Optional[str] = ..., base_path: _Optional[str] = ..., path_suffix: _Optional[str] = ..., url: _Optional[str] = ...) -> None: ...

class Route(_message.Message):
    __slots__ = ("name", "target")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    name: str
    target: str
    def __init__(self, name: _Optional[str] = ..., target: _Optional[str] = ...) -> None: ...

class Target(_message.Message):
    __slots__ = ("base_path", "copy_path_suffix", "copy_query_params", "country", "cn", "email_address", "expected_cn", "host", "ip", "locality", "name", "organization", "organization_unit", "port", "scheme", "state", "ssl_enabled", "url")
    BASE_PATH_FIELD_NUMBER: _ClassVar[int]
    COPY_PATH_SUFFIX_FIELD_NUMBER: _ClassVar[int]
    COPY_QUERY_PARAMS_FIELD_NUMBER: _ClassVar[int]
    COUNTRY_FIELD_NUMBER: _ClassVar[int]
    CN_FIELD_NUMBER: _ClassVar[int]
    EMAIL_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    EXPECTED_CN_FIELD_NUMBER: _ClassVar[int]
    HOST_FIELD_NUMBER: _ClassVar[int]
    IP_FIELD_NUMBER: _ClassVar[int]
    LOCALITY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_FIELD_NUMBER: _ClassVar[int]
    ORGANIZATION_UNIT_FIELD_NUMBER: _ClassVar[int]
    PORT_FIELD_NUMBER: _ClassVar[int]
    SCHEME_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    SSL_ENABLED_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    base_path: str
    copy_path_suffix: bool
    copy_query_params: bool
    country: str
    cn: str
    email_address: str
    expected_cn: str
    host: str
    ip: str
    locality: str
    name: str
    organization: str
    organization_unit: str
    port: int
    scheme: str
    state: str
    ssl_enabled: bool
    url: str
    def __init__(self, base_path: _Optional[str] = ..., copy_path_suffix: _Optional[bool] = ..., copy_query_params: _Optional[bool] = ..., country: _Optional[str] = ..., cn: _Optional[str] = ..., email_address: _Optional[str] = ..., expected_cn: _Optional[str] = ..., host: _Optional[str] = ..., ip: _Optional[str] = ..., locality: _Optional[str] = ..., name: _Optional[str] = ..., organization: _Optional[str] = ..., organization_unit: _Optional[str] = ..., port: _Optional[int] = ..., scheme: _Optional[str] = ..., state: _Optional[str] = ..., ssl_enabled: _Optional[bool] = ..., url: _Optional[str] = ...) -> None: ...

class Strings(_message.Message):
    __slots__ = ("strings",)
    STRINGS_FIELD_NUMBER: _ClassVar[int]
    strings: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, strings: _Optional[_Iterable[str]] = ...) -> None: ...

class FlowVariable(_message.Message):
    __slots__ = ("int32", "int64", "string", "bool", "double")
    INT32_FIELD_NUMBER: _ClassVar[int]
    INT64_FIELD_NUMBER: _ClassVar[int]
    STRING_FIELD_NUMBER: _ClassVar[int]
    BOOL_FIELD_NUMBER: _ClassVar[int]
    DOUBLE_FIELD_NUMBER: _ClassVar[int]
    int32: int
    int64: int
    string: str
    bool: bool
    double: float
    def __init__(self, int32: _Optional[int] = ..., int64: _Optional[int] = ..., string: _Optional[str] = ..., bool: _Optional[bool] = ..., double: _Optional[float] = ...) -> None: ...
