if(CONFIG_OPENBMC_BMCWEB)
    zephyr_library_named(bmcweb)
    zephyr_library_sources(
        ${ZEPHYR_CURRENT_MODULE_DIR}/src/webserver_main.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/src/webserver_cli.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/src/webserver_run.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/error_messages.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/registries.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/task_messages.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/heartbeat_messages.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/filter_expr_executor.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/filter_expr_printer.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/utils/json_utils.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/utils/time_utils.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/utils/dbus_utils.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/dbus_log_watcher.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/filesystem_log_watcher.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/subscription.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/redfish.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/src/dbus_singleton.cpp
        # ${ZEPHYR_CURRENT_MODULE_DIR}/src/bmcwebSetup.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/src/ossl_random.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/src/ssl_key_handler.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/src/json_html_serializer.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/http/mutual_tls.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/zephyr/dup_stub.c
    )
    zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/zephyr)
    zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/)
    zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/config)
    zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/http)
    zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/include)
    zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/lib)
    zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/include)
    zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/include/generated/enums)
    zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/include/utils)
    zephyr_library_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/include/registries)

    zephyr_library_link_libraries(basu)
    zephyr_library_link_libraries(boost)
    zephyr_library_link_libraries(nlohmann_json)
    zephyr_library_link_libraries(zephyr-osal)
    zephyr_library_link_libraries(sdbusplus)
    zephyr_library_link_libraries(tinyxml2)
    zephyr_library_link_libraries(CLI11)
    # zephyr_library_link_libraries(phosphor-user-manager)

    # Upstream passes this through meson options; keep the default (3-digit
    # Redfish message IDs) for the Zephyr build.

    zephyr_library_compile_definitions(
        BMCWEB_HYPERVISOR_COMPUTER_SYSTEM=0
        BMCWEB_REDFISH_HOST_LOGGER=0
        BMCWEB_REDFISH_CPU_LOG=0
        BMCWEB_REDFISH_BMC_JOURNAL=0
        BMCWEB_REDFISH_DUMP_LOG=0
        BMCWEB_REDFISH_NEW_POWERSUBSYSTEM_THERMALSUBSYSTEM=0
        BMCWEB_REDFISH_ALLOW_DEPRECATED_POWER_THERMAL=1
        BMCWEB_REDFISH_ALLOW_SIMPLE_UPDATE=0
        BMCWEB_REDFISH_SYSTEM_URI_NAME="system"
        BMCWEB_REDFISH_UPDATESERVICE_USE_DBUS=0
        BMCWEB_EXPERIMENTAL_REDFISH_MULTI_COMPUTER_SYSTEM=0
        BMCWEB_REDFISH_MANAGER_URI_NAME="BMC"
        BMCWEB_REDFISH_PROVISIONING_FEATURE=0
        BMCWEB_REDFISH_OEM_MANAGER_FAN_DATA=0
        BMCWEB_REDFISH_USE_3_DIGIT_MESSAGEID=0)
endif()
