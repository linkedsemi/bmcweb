#include "ssl_key_handler.hpp"

#include "bmcweb_config.h"

#include "logging.hpp"
#include "ossl_random.hpp"
#include "sessions.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl/verify_mode.hpp>
#include <boost/beast/core/file_base.hpp>
#include <boost/beast/core/file_posix.hpp>

#include <bit>
#include <cstddef>
#ifdef __ZEPHYR__
// memcmp() is used by the local nghttp2_select_alpn() replacement.
#include <cstring>
#endif /* __ZEPHYR__ */
#include <limits>
#include <system_error>
#include <utility>

extern "C"
{
#ifndef __ZEPHYR__
#include <nghttp2/nghttp2.h>
#include <openssl/types.h>
#endif /* __ZEPHYR__ */
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#ifdef __ZEPHYR__
// RSA_check_key()/EVP_PKEY_get1_RSA() are only used in the Zephyr
// verification path (wolfSSL's OpenSSL compat layer).
#include <openssl/rsa.h>
#endif /* __ZEPHYR__ */
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
}

#ifdef __ZEPHYR__
// nghttp2 is not available in the Zephyr build.  Provide a local
// nghttp2_select_alpn equivalent that mirrors nghttp2's ALPN helper
// (prefers h2, then http/1.1).  ALPN protocol ids are length-prefixed:
// <len><protocol>, e.g. the "h2" id is stored as {0x02, 'h', '2'}.
static int zephyrSelectAlpn(const unsigned char** out, unsigned char* outlen,
                            const unsigned char* in, unsigned int inlen,
                            const char* key, unsigned int keylen)
{
    unsigned int i = 0;
    while (i + keylen <= inlen)
    {
        const unsigned int entryLen =
            static_cast<unsigned int>(in[i]);

        // Reject malformed/truncated ALPN entries instead of stepping
        // past the end of the buffer.
        if (entryLen > inlen - i - 1)
        {
            return -1;
        }

        if (std::memcmp(&in[i], key, keylen) == 0)
        {
            *out = &in[i + 1];
            *outlen = in[i];
            return 0;
        }
        i += 1 + entryLen;
    }
    return -1;
}

static int nghttp2_select_alpn(const unsigned char** out,
                               unsigned char* outlen,
                               const unsigned char* in, unsigned int inlen)
{
    // Length-prefixed ALPN ids: {"\x02h2"} == "h2",
    // {"\x08http/1.1"} == "http/1.1".  sizeof()-1 keeps the embedded
    // length prefix and keylen in sync.
    static constexpr char h2Alpn[] = "\x02h2";
    static constexpr char http11Alpn[] = "\x08http/1.1";

    if (zephyrSelectAlpn(out, outlen, in, inlen, h2Alpn,
                         sizeof(h2Alpn) - 1) == 0)
    {
        return 1;
    }
    if (zephyrSelectAlpn(out, outlen, in, inlen, http11Alpn,
                         sizeof(http11Alpn) - 1) == 0)
    {
        return 0;
    }
    return -1;
}
#endif /* __ZEPHYR__ */

#include <boost/asio/ssl/context.hpp>
#include <boost/system/error_code.hpp>

#include <filesystem>
#include <memory>
#include <optional>
#include <random>
#include <string>

namespace ensuressl
{

static EVP_PKEY* createEcKey();

// Mozilla intermediate cipher suites v5.7
// Sourced from: https://ssl-config.mozilla.org/guidelines/5.7.json
constexpr const char* mozillaIntermediate =
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "DHE-RSA-AES128-GCM-SHA256:"
    "DHE-RSA-AES256-GCM-SHA384:"
    "DHE-RSA-CHACHA20-POLY1305";

// Trust chain related errors.`
bool isTrustChainError(int errnum)
{
    return (errnum == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) ||
           (errnum == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) ||
           (errnum == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) ||
           (errnum == X509_V_ERR_CERT_UNTRUSTED) ||
           (errnum == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE);
}

bool validateCertificate(X509* const cert)
{
    // Create an empty X509_STORE structure for certificate validation.
    X509_STORE* x509Store = X509_STORE_new();
    if (x509Store == nullptr)
    {
        BMCWEB_LOG_ERROR("Error occurred during X509_STORE_new call");
        return false;
    }

    // Load Certificate file into the X509 structure.
    X509_STORE_CTX* storeCtx = X509_STORE_CTX_new();
    if (storeCtx == nullptr)
    {
        BMCWEB_LOG_ERROR("Error occurred during X509_STORE_CTX_new call");
        X509_STORE_free(x509Store);
        return false;
    }

    int errCode = X509_STORE_CTX_init(storeCtx, x509Store, cert, nullptr);
    if (errCode != 1)
    {
        BMCWEB_LOG_ERROR("Error occurred during X509_STORE_CTX_init call");
        X509_STORE_CTX_free(storeCtx);
        X509_STORE_free(x509Store);
        return false;
    }

    errCode = X509_verify_cert(storeCtx);
    if (errCode == 1)
    {
        BMCWEB_LOG_INFO("Certificate verification is success");
        X509_STORE_CTX_free(storeCtx);
        X509_STORE_free(x509Store);
        return true;
    }
    if (errCode == 0)
    {
        errCode = X509_STORE_CTX_get_error(storeCtx);
        X509_STORE_CTX_free(storeCtx);
        X509_STORE_free(x509Store);
        if (isTrustChainError(errCode))
        {
            BMCWEB_LOG_DEBUG("Ignoring Trust Chain error. Reason: {}",
                             X509_verify_cert_error_string(errCode));
            return true;
        }
        BMCWEB_LOG_ERROR("Certificate verification failed. Reason: {}",
                         X509_verify_cert_error_string(errCode));
        return false;
    }

    BMCWEB_LOG_ERROR(
        "Error occurred during X509_verify_cert call. ErrorCode: {}", errCode);
    X509_STORE_CTX_free(storeCtx);
    X509_STORE_free(x509Store);
    return false;
}

#ifdef __ZEPHYR__
bool verifyOpensslKeyCert(const std::string& filepath)
{
    bool privateKeyValid = false;
    bool certValid = false;

    BMCWEB_LOG_INFO("Checking certs in file {}", filepath);

    /* Use wolfSSL's XFILE abstraction: stdio is not usable on the Zephyr
     * littlefs filesystem, and a memory BIO would fail on the two-block
     * PEM file. */
    XFILE file = XFOPEN(filepath.c_str(), "r");
    if (file != nullptr)
    {
        EVP_PKEY* pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
        if (pkey != nullptr)
        {
            /* wolfSSL's OpenSSL compat reports < 3.0; validate with the
             * legacy RSA/EC helpers. */
            RSA* rsa = EVP_PKEY_get1_RSA(pkey);
            if (rsa != nullptr)
            {
                if (RSA_check_key(rsa) == 1)
                {
                    privateKeyValid = true;
                }
                else
                {
                    BMCWEB_LOG_ERROR("Key not valid error number {}",
                                     ERR_get_error());
                }
                RSA_free(rsa);
            }
            else
            {
                EC_KEY* ec = EVP_PKEY_get1_EC_KEY(pkey);
                if (ec != nullptr)
                {
                    if (EC_KEY_check_key(ec) == 1)
                    {
                        privateKeyValid = true;
                    }
                    else
                    {
                        BMCWEB_LOG_ERROR("Key not valid error number {}",
                                         ERR_get_error());
                    }
                    EC_KEY_free(ec);
                }
            }

            if (privateKeyValid)
            {
                /* The PEM file may carry the certificate before or after the
                 * key; rewind so the X509 parse finds the certificate block. */
                XFSEEK(file, 0, XSEEK_SET);

                X509* x509 = PEM_read_X509(file, nullptr, nullptr, nullptr);
                if (x509 == nullptr)
                {
                    BMCWEB_LOG_ERROR("error getting x509 cert {}",
                                     ERR_get_error());
                }
                else
                {
                    certValid = validateCertificate(x509);
                    X509_free(x509);
                }
            }

            EVP_PKEY_free(pkey);
        }

        XFCLOSE(file);
    }
    else
    {
        BMCWEB_LOG_DEBUG("verifyOpensslKeyCert open fail: {}", filepath);
    }

    return certValid;
}
#else
std::string verifyOpensslKeyCert(const std::string& filepath)
{
    bool privateKeyValid = false;

    BMCWEB_LOG_INFO("Checking certs in file {}", filepath);
    boost::beast::file_posix file;
    boost::system::error_code ec;
    file.open(filepath.c_str(), boost::beast::file_mode::read, ec);
    if (ec)
    {
        return "";
    }
    bool certValid = false;
    std::string fileContents;
    fileContents.resize(static_cast<size_t>(file.size(ec)), '\0');
    file.read(fileContents.data(), fileContents.size(), ec);
    if (ec)
    {
        BMCWEB_LOG_ERROR("Failed to read file");
        return "";
    }

    BIO* bufio = BIO_new_mem_buf(static_cast<void*>(fileContents.data()),
                                 static_cast<int>(fileContents.size()));
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bufio, nullptr, nullptr, nullptr);
    BIO_free(bufio);
    if (pkey != nullptr)
    {
        EVP_PKEY_CTX* pkeyCtx =
            EVP_PKEY_CTX_new_from_pkey(nullptr, pkey, nullptr);

        if (pkeyCtx == nullptr)
        {
            BMCWEB_LOG_ERROR("Unable to allocate pkeyCtx {}", ERR_get_error());
        }
        else if (EVP_PKEY_check(pkeyCtx) == 1)
        {
            privateKeyValid = true;
        }
        else
        {
            BMCWEB_LOG_ERROR("Key not valid error number {}", ERR_get_error());
        }

        if (privateKeyValid)
        {
            BIO* bufio2 =
                BIO_new_mem_buf(static_cast<void*>(fileContents.data()),
                                static_cast<int>(fileContents.size()));
            X509* x509 = PEM_read_bio_X509(bufio2, nullptr, nullptr, nullptr);
            BIO_free(bufio2);
            if (x509 == nullptr)
            {
                BMCWEB_LOG_ERROR("error getting x509 cert {}", ERR_get_error());
            }
            else
            {
                certValid = validateCertificate(x509);
                X509_free(x509);
            }
        }

        EVP_PKEY_CTX_free(pkeyCtx);
        EVP_PKEY_free(pkey);
    }
    if (!certValid)
    {
        return "";
    }
    return fileContents;
}
#endif /* __ZEPHYR__ */

X509* loadCert(const std::string& filePath)
{
    BIO* certFileBio = BIO_new_file(filePath.c_str(), "rb");
    if (certFileBio == nullptr)
    {
        BMCWEB_LOG_ERROR("Error occurred during BIO_new_file call, FILE= {}",
                         filePath);
        return nullptr;
    }

    X509* cert = X509_new();
    if (cert == nullptr)
    {
        BMCWEB_LOG_ERROR("Error occurred during X509_new call, {}",
                         ERR_get_error());
        BIO_free(certFileBio);
        return nullptr;
    }

    if (PEM_read_bio_X509(certFileBio, &cert, nullptr, nullptr) == nullptr)
    {
        BMCWEB_LOG_ERROR(
            "Error occurred during PEM_read_bio_X509 call, FILE= {}", filePath);

        BIO_free(certFileBio);
        X509_free(cert);
        return nullptr;
    }
    BIO_free(certFileBio);
    return cert;
}

int addExt(X509* cert, int nid, const char* value)
{
    X509_EXTENSION* ex = nullptr;
    X509V3_CTX ctx{};
    X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, const_cast<char*>(value));
    if (ex == nullptr)
    {
        BMCWEB_LOG_ERROR("Error: In X509V3_EXT_conf_nidn: {}", value);
        return -1;
    }
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return 0;
}

#ifdef __ZEPHYR__
void generateSslCertificate(const std::string& filepath,
                            const std::string& cn)
{
    BMCWEB_LOG_INFO("Generating new keys");

    BMCWEB_LOG_INFO("Generating EC key");
    EVP_PKEY* pPrivKey = createEcKey();
    if (pPrivKey != nullptr)
    {
        BMCWEB_LOG_INFO("Generating x509 Certificates");
        // Use this code to directly generate a certificate
        X509* x509 = X509_new();
        if (x509 != nullptr)
        {
            // get a random number from the RNG for the certificate serial
            // number If this is not random, regenerating certs throws browser
            // errors
            bmcweb::OpenSSLGenerator gen;
            std::uniform_int_distribution<int> dis(
                1, std::numeric_limits<int>::max());
            int serial = dis(gen);

            ASN1_INTEGER_set(X509_get_serialNumber(x509), serial);

            /* Zephyr has no real RTC: wolfSSL's time() returns boot uptime,
             * so a time-relative validity window breaks across reboots
             * ("certificate not yet valid"). Use a fixed wide window. */
            ASN1_TIME_set_string(X509_get_notBefore(x509),
                                 "700101000000Z");
            ASN1_TIME_set_string(X509_get_notAfter(x509),
                                 "791231235959Z");

            // set the public key to the key we just generated
            X509_set_pubkey(x509, pPrivKey);

            // get the subject name
            X509_NAME* name = X509_get_subject_name(x509);

            using x509String = const unsigned char;
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            x509String* country = reinterpret_cast<x509String*>("US");
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            x509String* company = reinterpret_cast<x509String*>("OpenBMC");
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            x509String* cnStr = reinterpret_cast<x509String*>(cn.c_str());

            X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, country, -1, -1,
                                       0);
            X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, company, -1, -1,
                                       0);
            X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cnStr, -1, -1,
                                       0);
            // set the CSR options
            X509_set_issuer_name(x509, name);

            X509_set_version(x509, 2);
            addExt(x509, NID_basic_constraints, ("critical,CA:TRUE"));
            addExt(x509, NID_subject_alt_name, cn.c_str());
            addExt(x509, NID_subject_key_identifier, ("hash"));
            addExt(x509, NID_authority_key_identifier, ("keyid"));
            addExt(x509, NID_key_usage, ("digitalSignature, keyEncipherment"));
            addExt(x509, NID_ext_key_usage, ("serverAuth"));

            // Sign the certificate with our private key
            X509_sign(x509, pPrivKey, EVP_sha256());

            /* Write through wolfSSL's XFILE abstraction: stdio is not usable
             * on the Zephyr littlefs filesystem. */
            XFILE pFile = XFOPEN(filepath.c_str(), "w");
            if (pFile != nullptr)
            {
                BIO* bio = BIO_new_fp(pFile, BIO_NOCLOSE);
                if (bio != nullptr)
                {
                    int pkeyRet = PEM_write_bio_PrivateKey(
                        bio, pPrivKey, nullptr, nullptr, 0, nullptr, nullptr);
                    if (pkeyRet <= 0)
                    {
                        BMCWEB_LOG_ERROR(
                            "Failed to write pkey with code {}.  Ignoring.",
                            pkeyRet);
                    }
                    BIO_flush(bio);
                    BIO_free(bio);
                }
                PEM_write_X509(pFile, x509);
                XFCLOSE(pFile);
            }
            else
            {
                BMCWEB_LOG_DEBUG("generateSslCertificate open fail: {}",
                                 filepath);
            }
            X509_free(x509);
        }

        EVP_PKEY_free(pPrivKey);
        pPrivKey = nullptr;
    }

    // cleanup_openssl();
}
#else
// Writes a certificate to a path, ignoring errors
void writeCertificateToFile(const std::string& filepath,
                            const std::string& certificate)
{
    boost::system::error_code ec;
    boost::beast::file_posix file;
    file.open(filepath.c_str(), boost::beast::file_mode::write, ec);
    if (!ec)
    {
        file.write(certificate.data(), certificate.size(), ec);
        // ignore result
    }
}

std::string generateSslCertificate(const std::string& cn)
{
    BMCWEB_LOG_INFO("Generating new keys");

    std::string buffer;
    BMCWEB_LOG_INFO("Generating EC key");
    EVP_PKEY* pPrivKey = createEcKey();
    if (pPrivKey != nullptr)
    {
        BMCWEB_LOG_INFO("Generating x509 Certificates");
        // Use this code to directly generate a certificate
        X509* x509 = X509_new();
        if (x509 != nullptr)
        {
            // get a random number from the RNG for the certificate serial
            // number If this is not random, regenerating certs throws browser
            // errors
            bmcweb::OpenSSLGenerator gen;
            std::uniform_int_distribution<int> dis(
                1, std::numeric_limits<int>::max());
            int serial = dis(gen);

            ASN1_INTEGER_set(X509_get_serialNumber(x509), serial);

            // not before this moment
            X509_gmtime_adj(X509_get_notBefore(x509), 0);
            // Cert is valid for 10 years
            X509_gmtime_adj(X509_get_notAfter(x509),
                            60L * 60L * 24L * 365L * 10L);

            // set the public key to the key we just generated
            X509_set_pubkey(x509, pPrivKey);

            // get the subject name
            X509_NAME* name = X509_get_subject_name(x509);

            using x509String = const unsigned char;
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            x509String* country = reinterpret_cast<x509String*>("US");
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            x509String* company = reinterpret_cast<x509String*>("OpenBMC");
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            x509String* cnStr = reinterpret_cast<x509String*>(cn.c_str());

            X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, country, -1, -1,
                                       0);
            X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, company, -1, -1,
                                       0);
            X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, cnStr, -1, -1,
                                       0);
            // set the CSR options
            X509_set_issuer_name(x509, name);

            X509_set_version(x509, 2);
            addExt(x509, NID_basic_constraints, ("critical,CA:TRUE"));
            addExt(x509, NID_subject_alt_name, ("DNS:" + cn).c_str());
            addExt(x509, NID_subject_key_identifier, ("hash"));
            addExt(x509, NID_authority_key_identifier, ("keyid"));
            addExt(x509, NID_key_usage, ("digitalSignature, keyEncipherment"));
            addExt(x509, NID_ext_key_usage, ("serverAuth"));
#ifndef __ZEPHYR__
            addExt(x509, NID_netscape_comment, (x509Comment));
#endif

            // Sign the certificate with our private key
            X509_sign(x509, pPrivKey, EVP_sha256());

            BIO* bufio = BIO_new(BIO_s_mem());

            int pkeyRet = PEM_write_bio_PrivateKey(
                bufio, pPrivKey, nullptr, nullptr, 0, nullptr, nullptr);
            if (pkeyRet <= 0)
            {
                BMCWEB_LOG_ERROR(
                    "Failed to write pkey with code {}.  Ignoring.", pkeyRet);
            }

            char* data = nullptr;
            long int dataLen = BIO_get_mem_data(bufio, &data);
            buffer += std::string_view(data, static_cast<size_t>(dataLen));
            BIO_free(bufio);

            bufio = BIO_new(BIO_s_mem());
            pkeyRet = PEM_write_bio_X509(bufio, x509);
            if (pkeyRet <= 0)
            {
                BMCWEB_LOG_ERROR(
                    "Failed to write X509 with code {}.  Ignoring.", pkeyRet);
            }
            dataLen = BIO_get_mem_data(bufio, &data);
            buffer += std::string_view(data, static_cast<size_t>(dataLen));

            BIO_free(bufio);
            BMCWEB_LOG_INFO("Cert size is {}", buffer.size());
            X509_free(x509);
        }

        EVP_PKEY_free(pPrivKey);
        pPrivKey = nullptr;
    }

    // cleanup_openssl();
    return buffer;
}
#endif /* __ZEPHYR__ */

#ifdef __ZEPHYR__
EVP_PKEY* createEcKey()
{
    EVP_PKEY* pKey = nullptr;

    /* wolfSSL's OpenSSL compat reports < 3.0; use the legacy EC_KEY API,
     * which wolfSSL supports natively. */
    int eccgrp = 0;
    eccgrp = OBJ_txt2nid("secp384r1");

    EC_KEY* myecc = EC_KEY_new_by_curve_name(eccgrp);
    if (myecc != nullptr)
    {
        EC_KEY_set_asn1_flag(myecc, OPENSSL_EC_NAMED_CURVE);
        EC_KEY_generate_key(myecc);
        pKey = EVP_PKEY_new();
        if (pKey != nullptr)
        {
            if (EVP_PKEY_assign(pKey, EVP_PKEY_EC, myecc) != 0)
            {
                /* pKey owns myecc from now */
                if (EC_KEY_check_key(myecc) <= 0)
                {
                    BMCWEB_LOG_ERROR("EC_check_key failed");
                }
            }
            else
            {
                EVP_PKEY_free(pKey);
                pKey = nullptr;
            }
        }
    }

    return pKey;
}
#else
EVP_PKEY* createEcKey()
{
    EVP_PKEY* pKey = nullptr;

    // Create context for curve parameter generation.
    std::unique_ptr<EVP_PKEY_CTX, decltype(&::EVP_PKEY_CTX_free)> ctx{
        EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), &::EVP_PKEY_CTX_free};
    if (!ctx)
    {
        return nullptr;
    }

    // Set up curve parameters.
    EVP_PKEY* params = nullptr;
    if ((EVP_PKEY_paramgen_init(ctx.get()) <= 0) ||
        (EVP_PKEY_CTX_set_ec_param_enc(ctx.get(), OPENSSL_EC_NAMED_CURVE) <=
         0) ||
        (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_secp384r1) <=
         0) ||
        (EVP_PKEY_paramgen(ctx.get(), &params) <= 0))
    {
        return nullptr;
    }

    // Set up RAII holder for params.
    std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)> pparams{
        params, &::EVP_PKEY_free};

    // Set new context for key generation, using curve parameters.
    ctx.reset(EVP_PKEY_CTX_new_from_pkey(nullptr, params, nullptr));
    if (!ctx || (EVP_PKEY_keygen_init(ctx.get()) <= 0))
    {
        return nullptr;
    }

    // Generate key.
    if (EVP_PKEY_keygen(ctx.get(), &pKey) <= 0)
    {
        return nullptr;
    }

    return pKey;
}
#endif /* __ZEPHYR__ */

#ifdef __ZEPHYR__
void ensureOpensslKeyPresentAndValid(const std::string& filepath)
{
    bool pemFileValid = verifyOpensslKeyCert(filepath);

    if (!pemFileValid)
    {
        BMCWEB_LOG_WARNING("Error in verifying signature, regenerating");
        generateSslCertificate(filepath, "testhost");
    }
}
#else
std::string ensureOpensslKeyPresentAndValid(const std::string& filepath)
{
    std::string cert = verifyOpensslKeyCert(filepath);

    if (cert.empty())
    {
        BMCWEB_LOG_WARNING("Error in verifying signature, regenerating");
        cert = generateSslCertificate("testhost");
        if (cert.empty())
        {
            BMCWEB_LOG_ERROR("Failed to generate cert");
        }
        else
        {
            writeCertificateToFile(filepath, cert);
        }
    }
    return cert;
}
#endif /* __ZEPHYR__ */

static std::string ensureCertificate()
{
    namespace fs = std::filesystem;
#ifdef __ZEPHYR__
    // Zephyr mounts the filesystem below CONFIG_FS_ROOT_OVERLAY.
    fs::path oldcertPath =
        fs::path(CONFIG_FS_ROOT_OVERLAY "/home/root/server.pem");
    std::error_code ec;
    fs::remove(oldcertPath, ec);
    // Ignore failure to remove;  File might not exist.

    fs::path certPath = CONFIG_FS_ROOT_OVERLAY "/etc/ssl/certs/https/";
#else
    // Cleanup older certificate file existing in the system
    fs::path oldcertPath = fs::path("/home/root/server.pem");
    std::error_code ec;
    fs::remove(oldcertPath, ec);
    // Ignore failure to remove;  File might not exist.

    fs::path certPath = "/etc/ssl/certs/https/";
#endif /* __ZEPHYR__ */
    // if path does not exist create the path so that
    // self signed certificate can be created in the
    // path
    fs::path certFile = certPath / "server.pem";

    if (!fs::exists(certPath, ec))
    {
        fs::create_directories(certPath, ec);
    }
    BMCWEB_LOG_INFO("Building SSL Context file= {}", certFile.string());
    std::string sslPemFile(certFile);
#ifdef __ZEPHYR__
    ensuressl::ensureOpensslKeyPresentAndValid(sslPemFile);
    return sslPemFile;
#else
    return ensuressl::ensureOpensslKeyPresentAndValid(sslPemFile);
#endif /* __ZEPHYR__ */
}

static int nextProtoCallback(SSL* /*unused*/, const unsigned char** data,
                             unsigned int* len, void* /*unused*/)
{
    // First byte is the length.
    constexpr std::string_view h2 = "\x02h2";
    *data = std::bit_cast<const unsigned char*>(h2.data());
    *len = static_cast<unsigned int>(h2.size());
    return SSL_TLSEXT_ERR_OK;
}

static int alpnSelectProtoCallback(
    SSL* /*unused*/, const unsigned char** out, unsigned char* outlen,
    const unsigned char* in, unsigned int inlen, void* /*unused*/)
{
    int rv = nghttp2_select_alpn(out, outlen, in, inlen);
    if (rv == -1)
    {
        return SSL_TLSEXT_ERR_NOACK;
    }
    if (rv == 1)
    {
        BMCWEB_LOG_DEBUG("Selected HTTP2");
    }
    return SSL_TLSEXT_ERR_OK;
}

#ifdef __ZEPHYR__
static bool getSslContext(boost::asio::ssl::context& mSslContext,
                          const std::string& certFile)
{
    mSslContext.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2 |
        boost::asio::ssl::context::no_sslv3 |
        boost::asio::ssl::context::single_dh_use |
        boost::asio::ssl::context::no_tlsv1 |
        boost::asio::ssl::context::no_tlsv1_1);

    BMCWEB_LOG_DEBUG("Using default TrustStore location: {}", trustStorePath);
    mSslContext.add_verify_path(trustStorePath);

    if (!certFile.empty())
    {
        boost::system::error_code ec;

        mSslContext.use_certificate_file(certFile,
                                         boost::asio::ssl::context::pem, ec);
        if (ec)
        {
            return false;
        }
        mSslContext.use_private_key_file(certFile,
                                         boost::asio::ssl::context::pem, ec);
        if (ec)
        {
            BMCWEB_LOG_CRITICAL("Failed to open ssl pkey");
            return false;
        }
    }

    // Set up EC curves to auto (boost asio doesn't have a method for this)
    // There is a pull request to add this.  Once this is included in an asio
    // drop, use the right way
    // http://stackoverflow.com/questions/18929049/boost-asio-with-ecdsa-certificate-issue
    if (SSL_CTX_set_ecdh_auto(mSslContext.native_handle(), 1) != 1)
    {}

    if (SSL_CTX_set_cipher_list(mSslContext.native_handle(),
                                mozillaIntermediate) != 1)
    {
        BMCWEB_LOG_ERROR("Error setting cipher list");
        return false;
    }
    return true;
}
#else
static bool getSslContext(boost::asio::ssl::context& mSslContext,
                          const std::string& sslPemFile)
{
    mSslContext.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2 |
        boost::asio::ssl::context::no_sslv3 |
        boost::asio::ssl::context::single_dh_use |
        boost::asio::ssl::context::no_tlsv1 |
        boost::asio::ssl::context::no_tlsv1_1);

    BMCWEB_LOG_DEBUG("Using default TrustStore location: {}", trustStorePath);
    mSslContext.add_verify_path(trustStorePath);

    if (!sslPemFile.empty())
    {
        boost::system::error_code ec;

        boost::asio::const_buffer buf(sslPemFile.data(), sslPemFile.size());
        mSslContext.use_certificate(buf, boost::asio::ssl::context::pem, ec);
        if (ec)
        {
            return false;
        }
        mSslContext.use_private_key(buf, boost::asio::ssl::context::pem, ec);
        if (ec)
        {
            BMCWEB_LOG_CRITICAL("Failed to open ssl pkey");
            return false;
        }
    }

    // Set up EC curves to auto (boost asio doesn't have a method for this)
    // There is a pull request to add this.  Once this is included in an asio
    // drop, use the right way
    // http://stackoverflow.com/questions/18929049/boost-asio-with-ecdsa-certificate-issue
    if (SSL_CTX_set_ecdh_auto(mSslContext.native_handle(), 1) != 1)
    {}

    if (SSL_CTX_set_cipher_list(mSslContext.native_handle(),
                                mozillaIntermediate) != 1)
    {
        BMCWEB_LOG_ERROR("Error setting cipher list");
        return false;
    }
    return true;
}
#endif /* __ZEPHYR__ */

std::shared_ptr<boost::asio::ssl::context> getSslServerContext()
{
    boost::asio::ssl::context sslCtx(boost::asio::ssl::context::tls_server);

    auto certFile = ensureCertificate();
    if (!getSslContext(sslCtx, certFile))
    {
        BMCWEB_LOG_CRITICAL("Couldn't get server context");
        return nullptr;
    }
    const persistent_data::AuthConfigMethods& c =
        persistent_data::SessionStore::getInstance().getAuthMethodsConfig();

    if (c.tlsStrict)
    {
        BMCWEB_LOG_DEBUG("Setting verify peer");
        boost::asio::ssl::verify_mode mode =
            boost::asio::ssl::verify_peer |
            boost::asio::ssl::verify_fail_if_no_peer_cert;
        boost::system::error_code ec;
        sslCtx.set_verify_mode(mode, ec);
        if (ec)
        {
            BMCWEB_LOG_DEBUG("Failed to set verify mode {}", ec.message());
            return nullptr;
        }
    }

    SSL_CTX_set_options(sslCtx.native_handle(), SSL_OP_NO_RENEGOTIATION);

    if constexpr (BMCWEB_EXPERIMENTAL_HTTP2)
    {
        SSL_CTX_set_next_protos_advertised_cb(sslCtx.native_handle(),
                                              nextProtoCallback, nullptr);

        SSL_CTX_set_alpn_select_cb(sslCtx.native_handle(),
                                   alpnSelectProtoCallback, nullptr);
    }

    return std::make_shared<boost::asio::ssl::context>(std::move(sslCtx));
}

std::optional<boost::asio::ssl::context>
    getSSLClientContext(VerifyCertificate verifyCertificate)
{
    namespace fs = std::filesystem;

    boost::asio::ssl::context sslCtx(boost::asio::ssl::context::tls_client);

    // NOTE, this path is temporary;  In the future it will need to change to
    // be set per subscription.  Do not rely on this.
#ifdef __ZEPHYR__
    fs::path certPath =
        fs::path(CONFIG_FS_ROOT_OVERLAY "/etc/ssl/certs/https/client.pem");
    bool pemFileValid = verifyOpensslKeyCert(certPath.string());
    if (!pemFileValid || !getSslContext(sslCtx, certPath.string()))
#else
    fs::path certPath = "/etc/ssl/certs/https/client.pem";
    std::string cert = verifyOpensslKeyCert(certPath);
    if (!getSslContext(sslCtx, cert))
#endif /* __ZEPHYR__ */
    {
        return std::nullopt;
    }

    // Add a directory containing certificate authority files to be used
    // for performing verification.
    boost::system::error_code ec;
    sslCtx.set_default_verify_paths(ec);
    if (ec)
    {
        BMCWEB_LOG_ERROR("SSL context set_default_verify failed");
        return std::nullopt;
    }

    int mode = boost::asio::ssl::verify_peer;
    if (verifyCertificate == VerifyCertificate::NoVerify)
    {
        mode = boost::asio::ssl::verify_none;
    }

    // Verify the remote server's certificate
    sslCtx.set_verify_mode(mode, ec);
    if (ec)
    {
        BMCWEB_LOG_ERROR("SSL context set_verify_mode failed");
        return std::nullopt;
    }

    if (SSL_CTX_set_cipher_list(sslCtx.native_handle(), mozillaIntermediate) !=
        1)
    {
        BMCWEB_LOG_ERROR("SSL_CTX_set_cipher_list failed");
        return std::nullopt;
    }

    return {std::move(sslCtx)};
}

} // namespace ensuressl
