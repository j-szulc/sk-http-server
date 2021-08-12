#include <iostream>
#include <cstdlib>
#include <set>
#include <cstring>
#include <regex>
#include <unordered_map>
#include <sys/stat.h>
#include <fcntl.h>
#include <fstream>
#include <optional>
#include <filesystem>
#include <unistd.h>
#include <algorithm>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <future>
#include <csignal>

#define HTTP_VERSION "HTTP/1.1"
#define RE_HTTP_VERSION "HTTP\\/1\\.1"

#define CRLF "\r\n"
#define PROT "http://"
#define DEFAULT_LISTENING_PORT 8080
#define MAX_SIZE 8192
#define BLOCK_SIZE 8192
#define BUFFER_SIZE 10*8192
#define QUEUE_LENGTH 52

#define STATUS_OK 200
#define STATUS_MOVED 302
#define STATUS_INVALID_FMT 400
#define STATUS_NOT_FOUND 404
#define STATUS_SERVER_ERROR 500
#define STATUS_UNIMPLEMENTED 501

#define INT_TO_STR_AUX(X) #X
#define INT_TO_STR(X) INT_TO_STR_AUX( X )
#define RE_MAX_SIZE "{1," INT_TO_STR( MAX_SIZE ) "}"

#define CAPTURE(X) "(" X ")"
#define LOOKAHEAD(X) "(?=" X ")"
#define RE_NO_ZERO_UNTIL_WHITESPACE "[^\\0]*\\s"
#define RE_PATH "[a-zA-Z0-9\\-\\.\\/]" RE_MAX_SIZE LOOKAHEAD("\\s")
#define RE_BLOCK "[^ ]" RE_MAX_SIZE
#define RE_IPV4 "(?:\\d+\\.){3}\\d+"
#define RE_PORT "\\d+{1,5}"
#define RE_ALT_SERVER_ENTRY CAPTURE(RE_PATH) "\t" CAPTURE(RE_IPV4) "\t" CAPTURE(RE_PORT)
//#define RE_ALT_SERVER_ENTRY CAPTURE(RE_PATH)

#define RE_METHOD "GET|HEAD"

// TODO ignore case
#define RE_HEADER_FIELD_NAME "[a-z0-9A-Z\\-]" RE_MAX_SIZE
#define RE_OWS " *"
#define RE_HEADER_VALUE "[a-zA-Z0-9\\.\\-\\/\\\\]" RE_MAX_SIZE
#define RE_HEADER_FIELD CAPTURE(RE_HEADER_FIELD_NAME) ":" RE_OWS CAPTURE(RE_HEADER_VALUE) RE_OWS CRLF

#define RE_CRLF CRLF
#define RE_SP " "
#define RE_OWS " *"

#ifdef DEBUG
static const bool debug_disabled=false;
#else
static const bool debug_disabled = true;
#endif

#define debugStream \
    if (debug_disabled) {} \
    else std::cerr

using namespace std;

class PipeClosed : public exception {
public:
    using exception::exception;
};

void sigpipeHandler(int) {
    throw PipeClosed();
}

class InternetException : public exception {
    string msg;
    int responseCode;
    bool fatal;
public:
    InternetException(string msg, int responseCode) : msg(msg), responseCode(responseCode) {}

    int send(int fd, string additionalHeaders = "") const {
        string response = HTTP_VERSION " " + to_string(responseCode) + " " + msg + CRLF + additionalHeaders + CRLF;
        return write(fd, response.c_str(), response.size());

    }

    int sendAndClose(int fd) const {
        int len = send(fd, "Connection: close" CRLF);
        close(fd);
        return len;
    }

    void throwIfServerFault() const {}

};

class ServerException : public InternetException {
    string msg;
public:

    ServerException(string msg, int responseCode = STATUS_SERVER_ERROR) : InternetException(msg, responseCode) {}

    void throwIfServerFault() const {
        throw runtime_error(msg);
    }

};

class ClientException : public InternetException {
public:
    using InternetException::InternetException;
};

class NonFatalClientException : public ClientException {
public:
    using ClientException::ClientException;
};

void serverAssert(bool cond, string errorMsg, int responseCode = STATUS_SERVER_ERROR) {
    if (!cond) {
        cerr << errorMsg << endl;
        cerr.flush();
        //exit(EXIT_FAILURE);
        throw ServerException(errorMsg, responseCode);
    }
}

void
clientAssert(bool cond, string errorMsg = "Invalid format", int responseCode = STATUS_INVALID_FMT, bool fatal = true) {
    if (!cond) {
        //cerr << errorMsg << endl;
        //cerr.flush();
        //exit(EXIT_FAILURE);
        if (fatal)
            throw ClientException(errorMsg, responseCode);
        else
            throw NonFatalClientException(errorMsg, responseCode);
    }
}

template<typename T>
T &clientOptionalAssert(optional<T> opt, string errorMsg = "Invalid format", int responseCode = STATUS_INVALID_FMT,
                        bool fatal = true) {
    clientAssert(opt.has_value(), errorMsg, responseCode, fatal);
    return *opt;
}

void exitFailure(string message, const std::exception &e) {
    cerr << message << endl << e.what() << endl;
    cerr.flush();
    exit(EXIT_FAILURE);
}

void offlineAssert(bool cond, string errorMsg) {
    if (!cond) {
        cerr << errorMsg << endl;
        cerr.flush();
        exit(EXIT_FAILURE);
        //throw runtime_error(errorMsg);
    }
}

// Class that allows reading regex matches from a file descriptor
class BufferedStream;

class BufferedStreamIterator : public iterator<
        bidirectional_iterator_tag,
        char,
        ptrdiff_t,
        char *,
        char &
> {
private:
    BufferedStream *stream;
    ssize_t pos;
    ssize_t limit;
public:
    bool isEnd() const;

    BufferedStreamIterator(BufferedStream *stream, size_t pos, int limit = -1);

    BufferedStreamIterator();

    char operator*() const;

    BufferedStreamIterator &operator++();

    BufferedStreamIterator &operator--();

    bool operator==(const BufferedStreamIterator &other) const;

    bool operator!=(const BufferedStreamIterator &other) const;
};

class BufferedStream {
private:

    int fd;
    char buffer[BUFFER_SIZE];
    ssize_t bufferBegin, bufferEnd;
    bool eof;

    // Move buffer[bufferBegin:bufferEnd] to buffer[0:bufferEnd-bufferBegin]
    void alignBuffer() {
        if (bufferBegin != 0) {
            for (ssize_t i = bufferBegin; i < bufferEnd; i++) {
                buffer[i - bufferBegin] = buffer[i];
            }
            bufferEnd -= bufferBegin;
            bufferBegin = 0;
        }
    }

    // Refill buffer, pull new characters from the stream
    void pull() {
        if (!eof && bufferEnd < BUFFER_SIZE) {

            ssize_t len = read(fd, buffer + bufferEnd, BUFFER_SIZE - bufferEnd);
            serverAssert(len >= 0, "read error");
            if (len == 0) {
                eof = true;
            }
            bufferEnd += len;
        }
    }

    BufferedStreamIterator begin(int limit = -1) {
        return BufferedStreamIterator(this, 0, limit);
    }

    BufferedStreamIterator end() {
        return BufferedStreamIterator(this, BUFFER_SIZE);
    }

public:

    optional<char> getByte(int index) {
        if (index >= BUFFER_SIZE) {
            return nullopt;
        }
        while (index >= bufferEnd && !eof)
            pull();

        if (index >= bufferEnd) {
            return nullopt;
        }

        return make_optional(buffer[index]);
    }

    bool isPastTheEnd(size_t pos) {
        return !getByte(pos).has_value();;
    }

    bool closed() {
        return eof && bufferBegin == bufferEnd;
    }

    BufferedStream(int fd) : fd(fd), bufferBegin(0), bufferEnd(0), eof(false) {}

    // Look for the patergn rgx in the stream and return the first match m,
    // set the position of the buffer right past the last character of the match
    // (i.e. discard m.str().size() characters from the stream and leave the rest)
    optional<match_results<BufferedStreamIterator>> next(const regex &rgx, int limit = -1) {

        alignBuffer();

        match_results<BufferedStreamIterator> sm;
        regex_search(begin(limit), end(), sm, rgx,
                     regex_constants::match_continuous | regex_constants::match_not_eol | regex_constants::match_any);

        if (!sm.empty()) {
            debugStream << "Match position: " << sm.position() << endl;
            debugStream << "Match length: " << sm.length() << endl;
            bufferBegin = sm.position() + sm.length();
            return make_optional(sm);
        } else {
            debugStream << "Didn't find match" << endl;
            return nullopt;
        }
    }
};

bool BufferedStreamIterator::isEnd() const {
    return (limit != -1 && pos >= limit) || stream == nullptr || stream->isPastTheEnd(pos);
}

BufferedStreamIterator::BufferedStreamIterator(BufferedStream *stream, size_t pos, int limit) : stream(stream),
                                                                                                pos(pos),
                                                                                                limit(limit) {}

BufferedStreamIterator::BufferedStreamIterator() : stream(nullptr), pos(BUFFER_SIZE) {}

char BufferedStreamIterator::operator*() const {
    auto maybeChar = stream->getByte(pos);
    clientAssert(maybeChar.has_value(), "EOF", STATUS_INVALID_FMT);
    return *maybeChar;
}

BufferedStreamIterator &BufferedStreamIterator::operator++() {
    pos++;
    return *this;
}

BufferedStreamIterator &BufferedStreamIterator::operator--() {
    pos--;
    return *this;
}

bool BufferedStreamIterator::operator==(const BufferedStreamIterator &other) const {
    return (stream == other.stream && pos == other.pos) || (isEnd() && other.isEnd());
}

bool BufferedStreamIterator::operator!=(const BufferedStreamIterator &other) const {
    return !(*this == other);
}


class AltServerMap {

    unordered_map<string, string> serverMap;

public:

    explicit AltServerMap(const char *path, const regex &re) {

        int fd = open(path, O_RDONLY);

        offlineAssert(fd >= 0, "Server map file open exception");

        BufferedStream altServerFileStream(fd);
        optional<match_results<BufferedStreamIterator>> maybeMatch;

        while ((maybeMatch = altServerFileStream.next(re)).has_value()) {
            auto match = *maybeMatch;
            serverMap[match[1].str()] = match[2].str() + ":" + match[3].str();;
        }

        close(fd);
    }

    optional<string> where(const string &contentPath) {
        auto it = serverMap.find(contentPath);
        if (it == serverMap.end())
            return nullopt;
        else
            return make_optional(it->second);
    }
};

bool subpath(filesystem::path parent, filesystem::path child) {
    return search(child.begin(), child.end(), parent.begin(), parent.end()) != child.end();
}

optional<filesystem::path> get(filesystem::path request, filesystem::path root = filesystem::current_path()) {
    debugStream << "Requesting " << request.string() << " from " << root.string() << endl;
    error_code err;

    filesystem::path rootCanonicalCopy = filesystem::canonical(root, err);
    serverAssert(!err, "Can't get canonical path of " + root.string());

    filesystem::path result = filesystem::canonical(root += filesystem::path("/") / request, err);
    debugStream << "Result:  " << result.string() << endl;

    if (err || !subpath(rootCanonicalCopy, result) || !filesystem::exists(result)) {
        return nullopt;
    } else {
        return result;
    }

}

int sendFile(filesystem::path path, int fdTo, string method = "GET", bool close = false) {

    error_code err;
    int totalLen = filesystem::file_size(path, err);
    int fdFrom = open(path.string().c_str(), O_RDONLY);

    if (err || fdFrom < 0)
        return -1;

    string additionalHeaderFields = "";
    if (close) {
        additionalHeaderFields = "Connection: close " CRLF;
    }
    string header = HTTP_VERSION " " INT_TO_STR(STATUS_OK) " " "OK" CRLF \
                   "Content-Type: application/octet-stream " CRLF \
                   "Content-Length: " + to_string(totalLen) + CRLF \
                           + additionalHeaderFields + \
                    CRLF;

    write(fdTo, header.c_str(), header.size());

    if (method != "GET")
        return 0;

    if (fdFrom < 0)
        return fdFrom;

    char buffer[BLOCK_SIZE];
    int lenReceived = 1;
    int lenSent = 1;
    int i = 0;

    for (; i < totalLen && lenReceived >= 0 && lenSent > 0; i += lenReceived) {
        lenReceived = read(fdFrom, buffer, BLOCK_SIZE);
        if (lenReceived > 0)
            lenSent = write(fdTo, buffer, lenReceived);
    }

    return close ? 0 : lenSent;
}

int sendAlternative(int fd, string alt, string path) {

    string header = HTTP_VERSION " " INT_TO_STR(STATUS_MOVED) " " "OK" CRLF \
                   "Location: " PROT + alt + path + CRLF \
                   CRLF;

    return write(fd, header.c_str(), header.size());
}


int main(int argc, char **argv) {

    offlineAssert((argc >= 2), "Usage: server <public dir> <alt servers> [port - default 8080]");

    std::signal(SIGPIPE, sigpipeHandler);

    string altServerPath(argv[2]);
    regex re(RE_ALT_SERVER_ENTRY);
    AltServerMap altServerMap(altServerPath.c_str(), re);

    filesystem::path publicDirPath;
    filesystem::path absPublicDirPath;
    try {
        publicDirPath.assign(argv[1]);
        absPublicDirPath = filesystem::absolute(publicDirPath);
    } catch (const exception &e) {
        exitFailure("Public dir path invalid", e);
    }
    offlineAssert(exists(absPublicDirPath), "Public dir does not exist");
    try {
        filesystem::current_path(absPublicDirPath);
    } catch (const exception &e) {
        exitFailure("Can't open public dir", e);
    }
    cout << "Working in " << filesystem::current_path().string() << endl;

    int port = DEFAULT_LISTENING_PORT;
    if (argv[3] != nullptr) {
        port = stoi(argv[3]);
    }

    int sock = socket(PF_INET, SOCK_STREAM, 0);
    offlineAssert(sock >= 0, "Socket error");

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(port);

    offlineAssert(bind(sock, (struct sockaddr *) &server_address, sizeof(server_address)) >= 0, "Bind error");

    offlineAssert(listen(sock, QUEUE_LENGTH) >= 0, "Listen error");

    socklen_t len = sizeof(server_address);
    getsockname(sock, (struct sockaddr *) &server_address, &len); // in case of port 0, fetch the assigned port
    port = ntohs(server_address.sin_port);

    static const regex rgxMethod(RE_METHOD);
    static const regex rgxValidPathAhead(LOOKAHEAD(RE_PATH));
    static const regex rgxBlock(RE_BLOCK);
    static const regex rgxHttpVersion(RE_HTTP_VERSION);

    static const regex rgxHeaderField(RE_HEADER_FIELD, regex_constants::icase);
    static const regex rgxCrlf(RE_CRLF);
    static const regex rgxSp(RE_SP);
    static const regex rgxOws(RE_OWS);
    static const regex rgxNoZeroUntilWhitespace(RE_NO_ZERO_UNTIL_WHITESPACE);

    static const set<string> recognizedHeaders = {"content-length", "connection", "content-type", "server"};

    while (true) {
        struct sockaddr_in client_address;
        socklen_t client_address_len = sizeof(client_address);

        cout << "accepting client connections on port " << port << endl;

        int msg_sock = accept(sock, (struct sockaddr *) &client_address, &client_address_len);
        serverAssert(msg_sock >= 0, "Accept error");

        BufferedStream client(msg_sock);

        try {
            bool closeConnection = false;

            do {
                try {
                    debugStream << "Looking for method" << endl;
                    auto maybeMethod = client.next(rgxMethod);
                    auto method = clientOptionalAssert(maybeMethod, "Invalid method", STATUS_UNIMPLEMENTED).str();

                    debugStream << "Looking for SP" << endl;

                    clientAssert(client.next(rgxSp).has_value());

                    debugStream << "Got method " << method << endl;

                    debugStream << "Looking for path" << endl;

                    bool validPath = client.next(rgxValidPathAhead).has_value();

                    auto request = clientOptionalAssert(client.next(rgxBlock)).str();

                    debugStream << "Looking for SP" << endl;

                    clientAssert(client.next(rgxSp).has_value());

                    debugStream << "Looking for HTTP" << endl;

                    clientOptionalAssert(client.next(rgxHttpVersion), "Invalid / unsupported HTTP version",
                                         STATUS_INVALID_FMT);

                    debugStream << "Looking for CRLF" << endl;

                    clientAssert(client.next(rgxCrlf, sizeof(CRLF) - 1).has_value(),
                                 "Expected CRLF at the end of header fields",
                                 STATUS_INVALID_FMT);

                    debugStream << "Looking for Headers" << endl;

                    auto maybeHeaderLine = client.next(rgxHeaderField);

                    set<string> seenHeaders;

                    while (maybeHeaderLine.has_value() && !closeConnection) {
                        string name = (*maybeHeaderLine)[1].str();
                        string value = (*maybeHeaderLine)[2].str();

                        transform(name.begin(), name.end(), name.begin(),
                                  [](unsigned char c) { return tolower(c); });

                        debugStream << "Received header " << name << " with value " << value << endl;

                        if (recognizedHeaders.count(name) > 0) {
                            clientAssert(seenHeaders.insert(name).second, "Repeated header!", STATUS_INVALID_FMT);

                            clientAssert(recognizedHeaders.count(name) == 0 || name == "connection",
                                         "Unexpected header: " + name, STATUS_INVALID_FMT);
                        }

                        if (name == "connection" || value == "close")
                            closeConnection = true;
                        else
                            maybeHeaderLine = client.next(rgxHeaderField);
                    }

                    debugStream << "Looking for CRLF" << endl;

                    clientAssert(client.next(rgxCrlf, sizeof(CRLF) - 1).has_value(),
                                 "Expected CRLF at the end of header fields",
                                 STATUS_INVALID_FMT);

                    clientAssert(validPath, "Invalid path", STATUS_NOT_FOUND, false);

                    auto maybeAbsRequestPath = get(filesystem::path(request));
                    if (maybeAbsRequestPath.has_value()) {
                        clientAssert(
                                sendFile(*maybeAbsRequestPath, msg_sock, method, client.closed() || closeConnection) >=
                                0, "Send error", STATUS_NOT_FOUND, false);
                    } else {
                        auto maybeAlternative = altServerMap.where(request);
                        auto alternative = clientOptionalAssert(maybeAlternative, "Not found", STATUS_NOT_FOUND, false);

                        auto formattedPath = filesystem::weakly_canonical(request);

                        clientAssert(sendAlternative(msg_sock, alternative, formattedPath) >= 0, "Send alt error",
                                     STATUS_NOT_FOUND, false);
                    }
                } catch (const NonFatalClientException &e) {
                    if (client.closed() || closeConnection) {
                        e.sendAndClose(msg_sock);
                    } else {
                        e.send(msg_sock);
                    }
                }
            } while (!client.closed() && !closeConnection);
            close(msg_sock);
        } catch (const InternetException &e) {
            e.sendAndClose(msg_sock);
            e.throwIfServerFault();
        } catch (const PipeClosed &e) {
            cout << "Client disconnected" << endl;
            close(msg_sock);
        }
    }
}