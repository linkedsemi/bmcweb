

#pragma once

#include <boost/asio/ssl/context.hpp>

#include <optional>
#include <string>

namespace ensuressl
{

enum class VerifyCertificate
{
    Verify,
    NoVerify
};

#ifdef __ZEPHYR__
constexpr const char* trustStorePath = CONFIG_FS_ROOT_OVERLAY"/etc/ssl/certs/authority";
#else
constexpr const char* trustStorePath = "/etc/ssl/certs/authority";
#endif /* __ZEPHYR__ */
constexpr const char* x509Comment = "Generated from OpenBMC service";

bool isTrustChainError(int errnum);

bool validateCertificate(X509* cert);

#ifdef __ZEPHYR__
bool verifyOpensslKeyCert(const std::string& filepath);
#else
std::string verifyOpensslKeyCert(const std::string& filepath);
#endif /* __ZEPHYR__ */

X509* loadCert(const std::string& filePath);

int addExt(X509* cert, int nid, const char* value);

#ifdef __ZEPHYR__
void generateSslCertificate(const std::string& filepath,
                            const std::string& cn);
#else
std::string generateSslCertificate(const std::string& cn);
#endif /* __ZEPHYR__ */


#ifdef __ZEPHYR__
void ensureOpensslKeyPresentAndValid(const std::string& filepath);
#else
void writeCertificateToFile(const std::string& filepath,
                            const std::string& certificate);

std::string ensureOpensslKeyPresentAndValid(const std::string& filepath);
#endif /* __ZEPHYR__ */

std::shared_ptr<boost::asio::ssl::context> getSslServerContext();

std::optional<boost::asio::ssl::context>
    getSSLClientContext(VerifyCertificate verifyCertificate);

} // namespace ensuressl
