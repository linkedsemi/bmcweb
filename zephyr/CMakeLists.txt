if(CONFIG_OPENBMC_BMCWEB)
    zephyr_library_named(bmcweb)
    zephyr_library_sources(
        ${ZEPHYR_CURRENT_MODULE_DIR}/src/webserver_main.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/src/webserver_cli.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/src/webserver_run.cpp
        # ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/error_messages.cpp
        # ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/registries.cpp
        # ${ZEPHYR_CURRENT_MODULE_DIR}/redfish-core/src/utils/json_utils.cpp
        # ${ZEPHYR_CURRENT_MODULE_DIR}/src/dbus_singleton.cpp
        # ${ZEPHYR_CURRENT_MODULE_DIR}/src/bmcwebSetup.cpp
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

    zephyr_library_link_libraries(boost)
    zephyr_library_link_libraries(nlohmann_json)
    zephyr_library_link_libraries(zephyr-osal)
    zephyr_library_link_libraries(sdbusplus)
    zephyr_library_link_libraries(tinyxml2)
    zephyr_library_link_libraries(CLI11)
    # zephyr_library_link_libraries(phosphor-user-manager)

    # option(BMCWEB_ENABLE_LOGGING "Enable BMCWEB logging" ON)
    # option(BMCWEB_ENABLE_DEBUG "Enable BMCWEB debug mode" ON)
    # option(BMCWEB_ENABLE_BASIC_AUTHENTICATION "Enable basic authentication" ON)
    # option(BMCWEB_ENABLE_COOKIE_AUTHENTICATION "Enable cookie authentication" ON)
    # option(BMCWEB_ENABLE_HOST_SERIAL_WEBSOCKET "Enable host serial console WebSocket" ON)
    # option(BMCWEB_ENABLE_IBM_MANAGEMENT_CONSOLE "Enable the IBM management console specific functionality" ON)
    # option(BMCWEB_ENABLE_REDFISH "Enable Redfish APIs.  Paths are under /redfish/v1/" ON)
    # option(BMCWEB_ENABLE_REDFISH_OEM_MANAGER_FAN_DATA "Enables Redfish OEM fan data on the manager resource" ON)
    # option(BMCWEB_ENABLE_SESSION_AUTHENTICATION "Enable session authentication" ON)
    # option(BMCWEB_ENABLE_XTOKEN_AUTHENTICATION "Enable xtoken authentication" ON)

    # add_definitions(-DBMCWEB_ENABLE_LOGGING)
    # add_definitions(-DBMCWEB_ENABLE_DEBUG)
    # add_definitions(-DBMCWEB_ENABLE_BASIC_AUTHENTICATION)
    # add_definitions(-DBMCWEB_ENABLE_COOKIE_AUTHENTICATION)
    # add_definitions(-DBMCWEB_ENABLE_HOST_SERIAL_WEBSOCKET)
    # add_definitions(-DBMCWEB_ENABLE_IBM_MANAGEMENT_CONSOLE)
    # add_definitions(-DBMCWEB_ENABLE_REDFISH_OEM_MANAGER_FAN_DATA)
    # add_definitions(-DBMCWEB_ENABLE_SESSION_AUTHENTICATION)
    # add_definitions(-DBMCWEB_ENABLE_XTOKEN_AUTHENTICATION)
    # add_definitions(-DBMCWEB_ENABLE_SSL)
    # add_definitions(-DBMCWEB_ENABLE_REDFISH)

    # compilation fail
    # add_definitions(-DBMCWEB_ENABLE_MUTUAL_TLS_AUTHENTICATION)
    # add_definitions(-DBMCWEB_ENABLE_REDFISH_BMC_JOURNAL)
    # log
    # add_definitions(-DBMCWEB_ENABLE_REDFISH_HOST_LOGGER)
endif()
