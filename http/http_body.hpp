#pragma once

#ifdef __ZEPHYR__
#include "data_dirs.hpp"
#endif /* __ZEPHYR__ */
#include "duplicatable_file_handle.hpp"
#include "logging.hpp"
#ifdef __ZEPHYR__
#include "ossl_random.hpp"
#include "str_utility.hpp"
#endif /* __ZEPHYR__ */
#include "utility.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <boost/beast/core/buffers_range.hpp>
#include <boost/beast/core/file_posix.hpp>
#ifdef __ZEPHYR__
#include <boost/beast/http/error.hpp>
#endif /* __ZEPHYR__ */
#include <boost/beast/http/message.hpp>
#include <boost/system/error_code.hpp>

#include <cstdint>
#ifdef __ZEPHYR__
#include <cstdio>
#include <filesystem>
#include <string>
#include <zephyr/posix/dirent.h>
#endif /* __ZEPHYR__ */
#include <optional>
#include <string_view>

namespace bmcweb
{
#ifdef __ZEPHYR__
// Requests larger than this are streamed to a file instead of being buffered
// in RAM.  The Zephyr app heap is only a few MiB, so a single firmware image
// can easily exhaust it if kept in memory.
constexpr size_t httpBodyFileSpillThreshold = 1024UL * 1024UL;

// Non-file requests (JSON, small multipart, etc.) are rejected above this
// limit instead of being buffered to death.  Aligned with the spill
// threshold so everything above 1MiB either goes to disk or is rejected.
constexpr size_t httpBodyMaxInMemory = 1024UL * 1024UL;

// Spilled bodies are buffered in RAM and flushed to disk in batches of this
// size to avoid one small write per received chunk (frequent FAT writes are
// slow and cause extra wear).
constexpr size_t httpBodyWriteBatchSize = 64UL * 1024UL;

constexpr std::string_view uploadTmpSuffix = ".upload.tmp";

// Remove leftover spill files from previous runs.  A crash or power loss can
// leave .upload.tmp files behind and FATFS has no automatic cleanup.
inline void cleanupStaleUploads()
{
    DIR* dir = opendir(std::string(httpBodyTempDir).c_str());
    if (dir == nullptr)
    {
        return;
    }
    constexpr std::string_view suffix = uploadTmpSuffix;
    while (struct dirent* entry = readdir(dir))
    {
        std::string_view name(entry->d_name);
        if (name.ends_with(suffix))
        {
            std::string path =
                std::string(httpBodyTempDir) + "/" + std::string(name);
            ::unlink(path.c_str());
        }
    }
    closedir(dir);
}

#endif
struct HttpBody
{
    // Body concept requires specific naming of classes
    // NOLINTBEGIN(readability-identifier-naming)
    class writer;
    class reader;
    class value_type;
    // NOLINTEND(readability-identifier-naming)

    static std::uint64_t size(const value_type& body);
};

enum class EncodingType
{
    Raw,
    Base64,
};

class HttpBody::value_type
{
    DuplicatableFileHandle fileHandle;
    std::optional<size_t> fileSize;
    std::string strBody;
#ifdef __ZEPHYR__
    std::string tempFilePath;
#endif /* __ZEPHYR__ */

  public:
    value_type() = default;
    explicit value_type(std::string_view s) : strBody(s) {}
    explicit value_type(EncodingType e) : encodingType(e) {}
#ifdef __ZEPHYR__
    value_type(const value_type&) = default;
    value_type(value_type&&) noexcept = default;
    value_type& operator=(const value_type&) = default;
    value_type& operator=(value_type&&) noexcept = default;
    ~value_type()
    {
        removeTempFile();
    }
#endif /* __ZEPHYR__ */
    EncodingType encodingType = EncodingType::Raw;

    const boost::beast::file_posix& file() const
    {
        return fileHandle.fileHandle;
    }

#ifdef __ZEPHYR__
    boost::beast::file_posix& file()
    {
        return fileHandle.fileHandle;
    }
#endif /* __ZEPHYR__ */
    std::string& str()
    {
        return strBody;
    }

    const std::string& str() const
    {
        return strBody;
    }

    std::optional<size_t> payloadSize() const
    {
        if (!fileHandle.fileHandle.is_open())
        {
            return strBody.size();
        }
        if (fileSize)
        {
            if (encodingType == EncodingType::Base64)
            {
                return crow::utility::Base64Encoder::encodedSize(*fileSize);
            }
        }
        return fileSize;
    }

#ifdef __ZEPHYR__
    const std::string& tempFile() const
    {
        return tempFilePath;
    }

    void setTempFile(std::string path)
    {
        tempFilePath = std::move(path);
    }

    void refreshFileSize()
    {
        boost::system::error_code ec;
        uint64_t size = fileHandle.fileHandle.size(ec);
        if (!ec)
        {
            fileSize = static_cast<size_t>(size);
        }
    }

    void removeTempFile()
    {
        if (!tempFilePath.empty())
        {
            ::unlink(tempFilePath.c_str());
            tempFilePath.clear();
        }
    }
#endif /* __ZEPHYR__ */
    void clear()
    {
#ifdef __ZEPHYR__
        removeTempFile();
#endif /* __ZEPHYR__ */
        strBody.clear();
        strBody.shrink_to_fit();
        fileHandle.fileHandle = boost::beast::file_posix();
        fileSize = std::nullopt;
        encodingType = EncodingType::Raw;
    }

    void open(const char* path, boost::beast::file_mode mode,
              boost::system::error_code& ec)
    {
        fileHandle.fileHandle.open(path, mode, ec);
        if (ec)
        {
            return;
        }
        boost::system::error_code ec2;
        uint64_t size = fileHandle.fileHandle.size(ec2);
        if (!ec2)
        {
            BMCWEB_LOG_INFO("File size was {} bytes", size);
            fileSize = static_cast<size_t>(size);
        }
        else
        {
            BMCWEB_LOG_WARNING("Failed to read file size on {}", path);
        }

#ifndef __ZEPHYR__
        int fadvise = posix_fadvise(fileHandle.fileHandle.native_handle(), 0, 0,
                                    POSIX_FADV_SEQUENTIAL);
        if (fadvise != 0)
        {
            BMCWEB_LOG_WARNING("Fasvise returned {} ignoring", fadvise);
        }
#endif /* __ZEPHYR__ */
        ec = {};
    }

    void setFd(int fd, boost::system::error_code& ec)
    {
        fileHandle.fileHandle.native_handle(fd);

        boost::system::error_code ec2;
        uint64_t size = fileHandle.fileHandle.size(ec2);
        if (!ec2)
        {
            if (size != 0 && size < std::numeric_limits<size_t>::max())
            {
                fileSize = static_cast<size_t>(size);
            }
        }
        ec = {};
    }
};

class HttpBody::writer
{
  public:
    using const_buffers_type = boost::asio::const_buffer;

  private:
    std::string buf;
    crow::utility::Base64Encoder encoder;

    value_type& body;
    size_t sent = 0;
    // 64KB This number is arbitrary, and selected to try to optimize for larger
    // files and fewer loops over per-connection reduction in memory usage.
    // Nginx uses 16-32KB here, so we're in the range of what other webservers
    // do.
    constexpr static size_t readBufSize = 1024UL * 64UL;
    std::array<char, readBufSize> fileReadBuf{};

  public:
    template <bool IsRequest, class Fields>
    writer(boost::beast::http::header<IsRequest, Fields>& /*header*/,
           value_type& bodyIn) : body(bodyIn)
    {}

    static void init(boost::beast::error_code& ec)
    {
        ec = {};
    }

    boost::optional<std::pair<const_buffers_type, bool>>
        get(boost::beast::error_code& ec)
    {
        return getWithMaxSize(ec, std::numeric_limits<size_t>::max());
    }

    boost::optional<std::pair<const_buffers_type, bool>>
        getWithMaxSize(boost::beast::error_code& ec, size_t maxSize)
    {
        std::pair<const_buffers_type, bool> ret;
        if (!body.file().is_open())
        {
            size_t remain = body.str().size() - sent;
            size_t toReturn = std::min(maxSize, remain);
            ret.first = const_buffers_type(&body.str()[sent], toReturn);

            sent += toReturn;
            ret.second = sent < body.str().size();
            BMCWEB_LOG_INFO("Returning {} bytes more={}", ret.first.size(),
                            ret.second);
            return ret;
        }
        size_t readReq = std::min(fileReadBuf.size(), maxSize);
        BMCWEB_LOG_INFO("Reading {}", readReq);
        boost::system::error_code readEc;
        size_t read = body.file().read(fileReadBuf.data(), readReq, readEc);
        if (readEc)
        {
            if (readEc != boost::system::errc::operation_would_block &&
                readEc != boost::system::errc::resource_unavailable_try_again)
            {
                BMCWEB_LOG_CRITICAL("Failed to read from file {}",
                                    readEc.message());
                ec = readEc;
                return boost::none;
            }
        }

        std::string_view chunkView(fileReadBuf.data(), read);
        BMCWEB_LOG_INFO("Read {} bytes from file", read);
        // If the number of bytes read equals the amount requested, we haven't
        // reached EOF yet
        ret.second = read == readReq;
        if (body.encodingType == EncodingType::Base64)
        {
            buf.clear();
            buf.reserve(
                crow::utility::Base64Encoder::encodedSize(chunkView.size()));
            encoder.encode(chunkView, buf);
            if (!ret.second)
            {
                encoder.finalize(buf);
            }
            ret.first = const_buffers_type(buf.data(), buf.size());
        }
        else
        {
            ret.first = const_buffers_type(chunkView.data(), chunkView.size());
        }
        return ret;
    }
};

class HttpBody::reader
{
    value_type& value;
#ifdef __ZEPHYR__
    const boost::beast::http::fields& hdr;
    std::string writeBuf;
#endif /* __ZEPHYR__ */

  public:
#ifdef __ZEPHYR__
    template <bool IsRequest, class Fields>
    reader(boost::beast::http::header<IsRequest, Fields>& headers,
           value_type& body) : value(body), hdr(headers)
    {}
#else
    template <bool IsRequest, class Fields>
    reader(boost::beast::http::header<IsRequest, Fields>& /*headers*/,
           value_type& body) : value(body)
    {}
#endif /* __ZEPHYR__ */

#ifdef __ZEPHYR__
    void init(const boost::optional<std::uint64_t>& contentLength,
              boost::beast::error_code& ec)
    {
        std::string_view contentType =
            hdr[boost::beast::http::field::content_type];
        bool isUploadType =
            contentType.starts_with("application/octet-stream") ||
            contentType.starts_with("multipart/form-data");

        // Chunked uploads have no Content-Length, so they cannot be size
        // gated; spill them unconditionally to keep RAM usage bounded.
        std::string_view transferEncoding =
            hdr[boost::beast::http::field::transfer_encoding];
        bool isChunked = bmcweb::asciiIEquals(transferEncoding, "chunked");

        if (isUploadType &&
            (isChunked ||
             (contentLength &&
              *contentLength > httpBodyFileSpillThreshold)))
        {
            std::string tempPath = std::string(httpBodyTempDir) + "/." +
                                   bmcweb::getRandomUUID() + std::string(uploadTmpSuffix);
            value.open(tempPath.c_str(), boost::beast::file_mode::write, ec);
            if (ec)
            {
                BMCWEB_LOG_CRITICAL("Failed to open temp upload file {}: {}",
                                    tempPath, ec.message());
                return;
            }
            value.setTempFile(std::move(tempPath));
            ec = {};
            return;
        }

        if (contentLength && *contentLength > httpBodyMaxInMemory)
        {
            BMCWEB_LOG_WARNING(
                "Content-Length {} exceeds in-memory body limit {}, rejecting",
                *contentLength, httpBodyMaxInMemory);
            ec = boost::beast::http::error::body_limit;
            return;
        }

        if (contentLength)
        {
            if (!value.file().is_open())
            {
                value.str().reserve(static_cast<size_t>(*contentLength));
            }
        }
        ec = {};
    }
#else
    void init(const boost::optional<std::uint64_t>& contentLength,
              boost::beast::error_code& ec)
    {
        if (contentLength)
        {
            if (!value.file().is_open())
            {
                value.str().reserve(static_cast<size_t>(*contentLength));
            }
        }
        ec = {};
    }
#endif /* __ZEPHYR__ */

#ifdef __ZEPHYR__
    template <class ConstBufferSequence>
    std::size_t put(const ConstBufferSequence& buffers,
                    boost::system::error_code& ec)
    {
        size_t extra = boost::beast::buffer_bytes(buffers);
        for (const auto b : boost::beast::buffers_range_ref(buffers))
        {
            if (!value.tempFile().empty())
            {
                writeBuf.append(static_cast<const char*>(b.data()), b.size());
                if (writeBuf.size() >= httpBodyWriteBatchSize)
                {
                    value.file().write(writeBuf.data(), writeBuf.size(), ec);
                    if (ec)
                    {
                        return 0;
                    }
                    writeBuf.clear();
                }
                continue;
            }
            const char* ptr = static_cast<const char*>(b.data());
            value.str() += std::string_view(ptr, b.size());
        }
        ec = {};
        return extra;
    }
#else
    template <class ConstBufferSequence>
    std::size_t put(const ConstBufferSequence& buffers,
                    boost::system::error_code& ec)
    {
        size_t extra = boost::beast::buffer_bytes(buffers);
        for (const auto b : boost::beast::buffers_range_ref(buffers))
        {
            const char* ptr = static_cast<const char*>(b.data());
            value.str() += std::string_view(ptr, b.size());
        }
        ec = {};
        return extra;
    }
#endif /* __ZEPHYR__ */

#ifdef __ZEPHYR__
    void finish(boost::system::error_code& ec)
    {
        if (!value.tempFile().empty())
        {
            if (!writeBuf.empty())
            {
                value.file().write(writeBuf.data(), writeBuf.size(), ec);
                if (ec)
                {
                    return;
                }
                writeBuf.clear();
            }
            // FAT does not finalize the file size in the directory entry
            // until the file is closed; the handler renames the temp file, so
            // close it here to make sure the data and size are flushed.
            if (value.file().is_open())
            {
                value.file().close(ec);
                if (ec)
                {
                    return;
                }
            }
            value.refreshFileSize();
        }
        ec = {};
    }
#else
    static void finish(boost::system::error_code& ec)
    {
        ec = {};
    }
#endif /* __ZEPHYR__ */
};

inline std::uint64_t HttpBody::size(const value_type& body)
{
    std::optional<size_t> payloadSize = body.payloadSize();
    return payloadSize.value_or(0U);
}

} // namespace bmcweb
