#include "webserver_cli.hpp"
#ifdef __ZEPHYR__
#include "logging.hpp"
#endif /* __ZEPHYR__ */

#ifdef __ZEPHYR__
int bmcweb_main(int argc, char** argv) noexcept(false)
#else
int main(int argc, char** argv) noexcept(false)
#endif  /* __ZEPHYR__ */
{
#ifdef __ZEPHYR__
    try
    {
        return runCLI(argc, argv);
    }
    catch (const std::exception& e)
    {
        BMCWEB_LOG_CRITICAL("Threw exception to main: {}", e.what());
        return -1;
    }
    catch (...)
    {
        BMCWEB_LOG_CRITICAL("Threw exception to main");
        return -1;
    }
#else
    return runCLI(argc, argv);
#endif /* __ZEPHYR__ */
}
