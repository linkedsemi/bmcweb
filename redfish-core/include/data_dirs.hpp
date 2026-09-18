#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>

namespace redfish
{

// Redfish event log directory on Zephyr (the SD card); /var/log does not
// exist there and is created at startup.  Keep it in one place so the
// scan and the directory creation stay in sync.
constexpr std::string_view redfishLogDir = CONFIG_FS_ROOT_MNT "/var/log";

constexpr const char* redfishEventLogFile = CONFIG_FS_ROOT_MNT "/var/log/redfish";

constexpr const char* hostLoggerFolderPath = CONFIG_FS_ROOT_MNT "/var/log/console";

} // namespace redfish


namespace bmcweb
{

// Temporary upload files live here until the route commits them by renaming.
// Configurable: change this constant to move the spill location.
constexpr std::string_view httpBodyTempDir = CONFIG_FS_ROOT_MNT "/var/lib/bmcweb";

// Completed firmware images are stored here after an update.  Configurable:
// change this constant to move the final image location.
constexpr std::string_view httpBodyImageDir = CONFIG_FS_ROOT_MNT "/images";

// Create every directory the server needs at startup: the upload spill /
// image dirs (bmcweb) and the Redfish event log dir (Zephyr: SD card, which
// has no /var/log until we make it).
inline bool ensureDirs()
{
    std::error_code ec;
    std::filesystem::create_directories(std::string(httpBodyTempDir),
                                        ec);
    if (ec)
    {
        return false;
    }
    std::filesystem::create_directories(std::string(httpBodyImageDir),
                                        ec);
    if (ec)
    {
        return false;
    }
    std::filesystem::create_directories(std::string(redfish::redfishLogDir), ec);
    return !ec;
}

} // namespace bmcweb
