#pragma once

#include <cstdint>
#include <cstddef>
#include <string_view>

// clang-format off
// constexpr const int bmcwebInsecureDisableXssPrevention =
//     @BMCWEB_INSECURE_DISABLE_XSS_PREVENTION@;

// constexpr const bool bmcwebInsecureEnableQueryParams = 1;

// constexpr const size_t bmcwebHttpReqBodyLimitMb = 1024;

// constexpr const char* mesonInstallPrefix = "MESON_INSTALL_PREFIX";

// constexpr const bool bmcwebInsecureEnableHttpPushStyleEventing = 1;

constexpr std::string_view  BMCWEB_LOGGING_LEVEL = "ERROR";
constexpr const bool        BMCWEB_INSECURE_PUSH_STYLE_NOTIFICATION = false;
constexpr const bool        BMCWEB_META_TLS_COMMON_NAME_PARSING = false;

constexpr const bool        BMCWEB_BASIC_AUTH = true;
constexpr const bool        BMCWEB_SESSION_AUTH = true;
constexpr const bool        BMCWEB_XTOKEN_AUTH = true;
constexpr const bool        BMCWEB_COOKIE_AUTH = true;
constexpr const bool        BMCWEB_MUTUAL_TLS_AUTH = false;

constexpr std::string_view BMCWEB_MUTUAL_TLS_COMMON_NAME_PARSING_DEFAULT = "CommonName";

constexpr const bool BMCWEB_INSECURE_DISABLE_AUTH = false;
constexpr const bool BMCWEB_INSECURE_DISABLE_CSRF = false;
constexpr const bool BMCWEB_INSECURE_DISABLE_SSL = false;
constexpr const bool BMCWEB_INSECURE_IGNORE_CONTENT_TYPE = false;
constexpr const bool BMCWEB_INSECURE_ENABLE_REDFISH_QUERY = false;

constexpr const std::string_view BMCWEB_DNS_RESOLVER = "asio";//systemd-dbus

constexpr const size_t BMCWEB_HTTP_BODY_LIMIT = 30;
constexpr const size_t BMCWEB_HTTPS_PORT = 443;

constexpr const bool BMCWEB_REDFISH_AGGREGATION = false;
constexpr const bool BMCWEB_REDFISH_DBUS_LOG = false;
constexpr const bool BMCWEB_EXPERIMENTAL_REDFISH_DBUS_LOG_SUBSCRIPTION = false;

constexpr const bool BMCWEB_VM_WEBSOCKET = false;
constexpr const bool BMCWEB_VM_NBDPROXY = false;

constexpr const bool BMCWEB_EXPERIMENTAL_HTTP2 = false;
//webserver_run.cpp
constexpr const bool BMCWEB_GOOGLE_API = false;
constexpr const bool BMCWEB_IBM_MANAGEMENT_CONSOLE = false;
constexpr const bool BMCWEB_HOST_SERIAL_SOCKET = false;
constexpr const bool BMCWEB_REST = true;
constexpr const bool BMCWEB_REDFISH = true;
constexpr const bool BMCWEB_KVM = false;
constexpr const bool BMCWEB_STATIC_HOSTING = true;


// clang-format on
