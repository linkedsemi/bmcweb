#include "webserver_cli.hpp"
#ifdef __ZEPHYR__
int bmcweb_main(int argc, char** argv) noexcept(false)
#else
int main(int argc, char** argv) noexcept(false)
#endif  /* __ZEPHYR__ */
{
    return runCLI(argc, argv);
}
