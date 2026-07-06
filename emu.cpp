#include <iostream>
#include <windows.h>
#include <winhttp.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <regex>
#include <chrono>
#include <atomic>
#include <algorithm>
#include <cstdio>
#include <process.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")

std::atomic<bool> g_Shutdown(false);
std::mutex g_ConsoleMutex;
std::mutex g_SessionMutex;
std::mutex g_LogMutex;
bool g_SessionActive = false;
bool g_PhpServerRunning = false;
bool g_VgcStoppedLogged = false;

std::string g_CachedToken;
std::string g_CachedSid;
bool g_SessionInitialized = false;
HANDLE g_PipeHandle = INVALID_HANDLE_VALUE;
int g_HeartbeatCount = 0;
bool g_NeedsValidation = false;

const wchar_t* VANGUARD_PIPE_NAME = L"\\\\.\\pipe\\933823D3-C77B-4BAE-89D7-A92B567236BC";
const wchar_t* VALORANT_EXE_NAME = L"VALORANT-Win64-Shipping.exe";

const char* PHP_GATEWAY_HOST = "vanguard-relay.onrender.com";
const char* PHP_GATEWAY_PATH = "/gateway.php";
const wchar_t* VANGUARD_SERVERS[] = { L"na.vg.ac.pvp.net", L"eu.vg.ac.pvp.net" };
const int VANGUARD_PORT = 8443;
const char* LOG_FILE = "vgc_emulator.log";

const char* RIOT_BLOCKED_HOSTS[] = {
    "*.logs.riotgames.com",
    "*.analytics.riotgames.com",
    "*.telemetry.riotgames.com",
    "*.cm.riotgames.com",
    "*.riot.mobygames.com",
    "127.0.0.1"
};

#pragma pack(push, 1)
struct VanguardHeader {
    uint32_t magic;
    uint32_t length;
    uint32_t type;
    uint32_t padding1[3];
    uint32_t payloadSize;
    uint32_t padding2[2];
};
#pragma pack(pop)

void Log(const std::string& prefix, const std::string& message, int colorCode = 7) {
    std::lock_guard<std::mutex> lock(g_ConsoleMutex);
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, colorCode);
    std::cout << "[" << prefix << "] " << message << std::endl;
    SetConsoleTextAttribute(hConsole, 7);
    
    std::lock_guard<std::mutex> logLock(g_LogMutex);
    FILE* f = fopen(LOG_FILE, "a");
    if (f) {
        time_t now = time(NULL);
        char timeStr[32];
        strftime(timeStr, sizeof(timeStr), "%H:%M:%S", localtime(&now));
        fprintf(f, "[%s][%s] %s\n", timeStr, prefix.c_str(), message.c_str());
        fclose(f);
    }
}

void BlockRiotTelemetry() {
    Log("BLOCK", "Blocking Riot telemetry via hosts file...", 14);
    
    const char* hosts[] = {
        "logs.riotgames.com",
        "analytics.riotgames.com", 
        "telemetry.riotgames.com",
        "cm.riotgames.com",
        "riotgeo.pp.ublip.com"
    };
    
    char hostsPath[MAX_PATH];
    GetSystemDirectoryA(hostsPath, MAX_PATH);
    strcat_s(hostsPath, "\\drivers\\etc\\hosts");
    
    FILE* f = fopen(hostsPath, "a");
    if (f) {
        fprintf(f, "\n# VGC Emulator Block - DO NOT EDIT\n");
        for (const char* host : hosts) {
            fprintf(f, "127.0.0.1 %s\n", host);
            fprintf(f, "127.0.0.1 *.%s\n", host);
        }
        fclose(f);
        
        system("ipconfig /flushdns >nul 2>&1");
        Log("BLOCK", "Riot telemetry blocked", 10);
    } else {
        Log("BLOCK", "Failed to modify hosts file", 12);
    }
}

void UnblockRiotTelemetry() {
    Log("BLOCK", "Unblocking Riot telemetry...", 14);
    
    char hostsPath[MAX_PATH];
    GetSystemDirectoryA(hostsPath, MAX_PATH);
    strcat_s(hostsPath, "\\drivers\\etc\\hosts");
    
    FILE* f = fopen(hostsPath, "r");
    FILE* temp = fopen("hosts.tmp", "w");
    
    if (f && temp) {
        char line[512];
        bool inBlock = false;
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "# VGC Emulator Block")) {
                inBlock = true;
                continue;
            }
            if (inBlock && line[0] != '\n' && line[0] != '#' && strstr(line, "127.0.0.1 ") == nullptr) {
                inBlock = false;
            }
            if (!inBlock) {
                fputs(line, temp);
            }
        }
        fclose(f);
        fclose(temp);
        remove(hostsPath);
        rename("hosts.tmp", hostsPath);
        
        system("ipconfig /flushdns >nul 2>&1");
        Log("BLOCK", "Riot telemetry unblocked", 10);
    } else {
        if (f) fclose(f);
        if (temp) fclose(temp);
    }
}

bool PhpGatewayForward(const std::string& payloadB64, std::string& outResponse) {
    std::string jsonBody = "{\"action\":\"forward\",\"response\":\"" + payloadB64 + "\"}";
    return SendToPhpGateway(jsonBody, outResponse);
}

bool ExtractFromPacket(const std::vector<uint8_t>& payload, std::string& token, std::string& sid) {
    std::string payloadStr(payload.begin(), payload.end());
    
    std::regex tokenRegex(R"(eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)");
    std::smatch match;
    if (std::regex_search(payloadStr, match, tokenRegex)) {
        token = match.str(0);
    }
    
    std::regex sidRegex(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
    std::vector<std::string> uuids;
    while (std::regex_search(payloadStr, match, sidRegex)) {
        uuids.push_back(match.str(0));
        payloadStr = match.suffix().str();
    }
    
    if (uuids.size() >= 2) {
        sid = uuids[1];
    } else if (uuids.size() == 1) {
        sid = uuids[0];
    }
    
    return !token.empty();
}

std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string result(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &result[0], size, NULL, NULL);
    return result;
}

std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring result(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &result[0], size);
    return result;
}

std::string Base64Encode(const std::vector<uint8_t>& data) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    int i = 0;
    int val = 0;
    
    for (unsigned char c : data) {
        val = (val << 8) + c;
        i += 8;
        while (i >= 6) {
            result += table[(val >> (i - 6)) & 0x3F];
            i -= 6;
        }
    }
    if (i > 0) {
        val <<= (6 - i);
        result += table[val & 0x3F];
    }
    while (result.size() % 4 && !result.empty()) result += '=';
    return result;
}

std::vector<uint8_t> Base64Decode(const std::string& str) {
    static const uint8_t table[] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
        64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64
    };
    
    std::vector<uint8_t> result;
    int val = 0;
    int bits = 0;
    
    for (char c : str) {
        if (c == '=' || c < 0) break;
        uint8_t v = table[(unsigned char)c];
        if (v == 64) continue;
        val = (val << 6) + v;
        bits += 6;
        if (bits >= 8) {
            result.push_back((val >> (bits - 8)) & 0xFF);
            bits -= 8;
        }
    }
    return result;
}

bool HttpPost(const std::wstring& server, int port, const std::wstring& path,
              const std::string& body, std::string& response, bool isHttps = false,
              const wchar_t* customHeaders = nullptr) {
    char dbgMsg[256];
    sprintf_s(dbgMsg, "HttpPost: server=%S port=%d path=%S body_len=%zu", server.c_str(), port, path.c_str(), body.size());
    Log("HTTP", dbgMsg, 10);
    
    DWORD flags = (isHttps ? WINHTTP_FLAG_SECURE : 0);
    HINTERNET hSession = WinHttpOpen(L"VGC-Emulator/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        Log("HTTP", "WinHttpOpen failed", 12);
        return false;
    }

    HINTERNET hConnect = WinHttpConnect(hSession, server.c_str(), (INTERNET_PORT)port, 0);
    if (!hConnect) {
        Log("HTTP", "WinHttpConnect failed", 12);
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), NULL, NULL, NULL, flags);
    if (!hRequest) {
        DWORD err = GetLastError();
        char errMsg[128];
        sprintf_s(errMsg, "WinHttpOpenRequest failed: %lu", err);
        Log("HTTP", errMsg, 12);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::wstring headers = customHeaders ? std::wstring(customHeaders) : L"Content-Type: application/json\r\n";
    BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1, (LPVOID)body.c_str(), (DWORD)body.size(), (DWORD)body.size(), 0);

    if (!bResults) {
        DWORD err = GetLastError();
        char errMsg[128];
        sprintf_s(errMsg, "WinHttpSendRequest failed: %lu", err);
        Log("HTTP", errMsg, 12);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        DWORD err = GetLastError();
        char errMsg[128];
        sprintf_s(errMsg, "WinHttpReceiveResponse failed: %lu", err);
        Log("HTTP", errMsg, 12);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }
    
    DWORD dwSize = 0;
    do {
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            DWORD err = GetLastError();
            char errMsg[128];
            sprintf_s(errMsg, "WinHttpQueryDataAvailable failed: %lu", err);
            Log("HTTP", errMsg, 12);
            break;
        }
        if (dwSize) {
            std::vector<char> buf(dwSize + 1);
            DWORD dwRead = 0;
            if (WinHttpReadData(hRequest, buf.data(), dwSize, &dwRead)) {
                response.append(buf.data(), dwRead);
            }
        }
    } while (dwSize > 0);
    
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return bResults != 0;
}

bool SendToPhpGateway(const std::string& jsonBody, std::string& outResponse) {
    std::string response;
    bool success = HttpPost(Utf8ToWide(PHP_GATEWAY_HOST), 443, L"/gateway.php", jsonBody, response, true);
    if (success && !response.empty()) {
        outResponse = response;
        return true;
    }
    return false;
}

bool PhpGatewayAuth(const std::string& token, const std::string& sid, const std::string& game, std::string& outResponse) {
    std::string jsonBody = "{\"action\":\"auth\",\"game\":\"" + game + "\",\"gametoken\":\"" + token + "\",\"sid\":\"" + sid + "\"}";
    return SendToPhpGateway(jsonBody, outResponse);
}

bool PhpGatewayForward(const std::string& payloadB64, std::string& outResponse) {
    std::string jsonBody = "{\"action\":\"forward\",\"response\":\"" + payloadB64 + "\"}";
    return SendToPhpGateway(jsonBody, outResponse);
}

bool PhpGatewayAccess(const std::string& responseB64, std::string& outResponse) {
    std::string jsonBody = "{\"action\":\"access\",\"response\":\"" + responseB64 + "\"}";
    return SendToPhpGateway(jsonBody, outResponse);
}

bool SendToVanguard(const std::string& payload, std::string& outResponse) {
    for (const wchar_t* server : VANGUARD_SERVERS) {
        std::string response;
        if (HttpPost(server, VANGUARD_PORT, L"/vanguard/v1/gateway", payload, response, true, L"Content-Type: application/x-protobuf\r\n")) {
            if (!response.empty()) {
                outResponse = response;
                return true;
            }
        }
    }
    return false;
}

std::vector<uint8_t> CraftAuthResponse(uint32_t incomingMagic, int protocolVersion, const std::vector<uint8_t>& uuidBytes) {
    std::vector<uint8_t> response;
    VanguardHeader header = {0};
    header.magic = incomingMagic + 1;
    header.type = 1;
    
    std::vector<uint8_t> payload;
    uint64_t timestamp = GetTickCount64();
    
    switch (protocolVersion) {
        case 1:
            header.length = 0x28;
            header.payloadSize = 8;
            payload.resize(8, 0);
            break;
        case 2:
            header.length = 0x28;
            header.payloadSize = 8;
            if (uuidBytes.size() >= 8) {
                payload.assign(uuidBytes.begin(), uuidBytes.begin() + 8);
            } else {
                payload.resize(8, 0);
            }
            break;
        case 3:
            header.length = 0x38;
            header.payloadSize = 16;
            if (uuidBytes.size() >= 16) {
                payload.assign(uuidBytes.begin(), uuidBytes.begin() + 16);
            } else {
                payload.resize(16, 0);
            }
            break;
        case 4:
            header.length = 0x28;
            header.payloadSize = 8;
            payload.resize(8);
            memcpy(payload.data(), &timestamp, 8);
            break;
        case 5:
            header.length = 0x40;
            header.payloadSize = 24;
            if (uuidBytes.size() >= 16) {
                payload.insert(payload.end(), uuidBytes.begin(), uuidBytes.begin() + 16);
            } else {
                payload.resize(16, 0);
            }
            payload.resize(24);
            memcpy(payload.data() + 16, &timestamp, 8);
            break;
    }
    
    uint8_t* headerPtr = reinterpret_cast<uint8_t*>(&header);
    response.insert(response.end(), headerPtr, headerPtr + sizeof(VanguardHeader));
    response.insert(response.end(), payload.begin(), payload.end());
    
    return response;
}

std::vector<uint8_t> CraftAuthResponseSimple(uint32_t incomingMagic) {
    VanguardHeader header = {0};
    header.magic = incomingMagic + 1;
    header.type = 1;
    header.length = 0x28;
    header.payloadSize = 8;
    
    std::vector<uint8_t> response;
    uint8_t* headerPtr = reinterpret_cast<uint8_t*>(&header);
    response.insert(response.end(), headerPtr, headerPtr + sizeof(VanguardHeader));
    response.resize(response.size() + 8, 0);
    
    return response;
}

std::vector<uint8_t> CraftTicketPacket(const std::vector<uint8_t>& ticket) {
    std::vector<uint8_t> packet;
    uint32_t ticketLen = (uint32_t)ticket.size();
    uint32_t totalLen = 36 + ticketLen;
    
    VanguardHeader header = {0};
    header.magic = 0x000003E9;
    header.length = totalLen;
    header.type = 1;
    header.padding1[0] = 0;
    header.padding1[1] = 0;
    header.padding1[2] = 0;
    header.payloadSize = ticketLen;
    header.padding2[0] = 0;
    header.padding2[1] = 0;
    
    uint8_t* headerPtr = reinterpret_cast<uint8_t*>(&header);
    packet.insert(packet.end(), headerPtr, headerPtr + sizeof(VanguardHeader));
    packet.insert(packet.end(), ticket.begin(), ticket.end());
    
    return packet;
}

bool InjectTicket(const std::vector<uint8_t>& ticket) {
    if (g_PipeHandle == INVALID_HANDLE_VALUE) {
        g_PipeHandle = CreateFileW(
            VANGUARD_PIPE_NAME,
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );
    }
    
    if (g_PipeHandle == INVALID_HANDLE_VALUE) {
        Log("INJECT", "Failed to open pipe for ticket injection", 12);
        return false;
    }
    
    std::vector<uint8_t> packet = CraftTicketPacket(ticket);
    DWORD bytesWritten = 0;
    
    BOOL result = WriteFile(g_PipeHandle, packet.data(), (DWORD)packet.size(), &bytesWritten, NULL);
    if (result && bytesWritten == packet.size()) {
        Log("INJECT", "Ticket injected successfully (" + std::to_string(bytesWritten) + " bytes)", 10);
        FlushFileBuffers(g_PipeHandle);
        return true;
    }
    
    Log("INJECT", "Failed to inject ticket", 12);
    return false;
}

void ClientHandler(HANDLE hPipe) {
    Log("C", "Client connected to pipe!", 10);
    
    g_PipeHandle = hPipe;
    
    std::vector<uint8_t> buffer(0x4000);
    DWORD bytesRead;
    std::string cachedToken;
    std::string cachedSid;
    
    while (!g_Shutdown) {
        if (!ReadFile(hPipe, buffer.data(), buffer.size(), &bytesRead, NULL) || bytesRead == 0) {
            break;
        }
        
        if (bytesRead >= sizeof(VanguardHeader)) {
            VanguardHeader* hdr = reinterpret_cast<VanguardHeader*>(buffer.data());
            uint32_t magic = hdr->magic;
            uint32_t type = hdr->type;
            
            char logMsg[128];
            sprintf_s(logMsg, "magic=0x%08X type=%u bytes=%lu", magic, type, bytesRead);
            Log("RECV", logMsg, 14);
            
            std::vector<uint8_t> response;
            DWORD bytesWritten;
            
            switch (type) {
                case 1:
                {
                    g_HeartbeatCount++;
                    
                    bool needsValidation = (g_NeedsValidation || g_HeartbeatCount % 30 == 0);
                    
                    if (needsValidation) {
                        Log("HEARTBEAT", "Periodic validation (count=" + std::to_string(g_HeartbeatCount) + ")", 11);
                        
                        std::string cachedToken, cachedSid;
                        {
                            std::lock_guard<std::mutex> lock(g_SessionMutex);
                            cachedToken = g_CachedToken;
                            cachedSid = g_CachedSid;
                        }
                        
                        if (!cachedToken.empty() && !cachedSid.empty()) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(200 + rand() % 300));
                            
                            std::string phpAuthResp;
                            if (PhpGatewayAuth(cachedToken, cachedSid, "valo", phpAuthResp)) {
                                std::regex dataRegex(R"x(\"data\"\s*:\s*\"([^\"]+)\")x");
                                std::smatch dataMatch;
                                if (std::regex_search(phpAuthResp, dataMatch, dataRegex)) {
                                    std::string b64Data = dataMatch.str(1);
                                    
                                    std::string vgRespB64;
                                    if (PhpGatewayForward(b64Data, vgRespB64)) {
                                        std::smatch forwardMatch;
                                        if (std::regex_search(vgRespB64, forwardMatch, dataRegex)) {
                                            std::string vanguardResponseB64 = forwardMatch.str(1);
                                            
                                            std::string accessResponse;
                                            if (PhpGatewayAccess(vanguardResponseB64, accessResponse)) {
                                                std::smatch accessMatch;
                                                if (std::regex_search(accessResponse, accessMatch, dataRegex)) {
                                                    std::string accessB64 = accessMatch.str(1);
                                                    
                                                    std::string finalResponseB64;
                                                    if (PhpGatewayForward(accessB64, finalResponseB64)) {
                                                        Log("HEARTBEAT", "Validation OK", 10);
                                                        g_NeedsValidation = false;
                                                        response = CraftAuthResponseSimple(magic);
                                                    } else {
                                                        response.assign(buffer.begin(), buffer.begin() + bytesRead);
                                                    }
                                                } else {
                                                    response.assign(buffer.begin(), buffer.begin() + bytesRead);
                                                }
                                            } else {
                                                response.assign(buffer.begin(), buffer.begin() + bytesRead);
                                            }
                                        } else {
                                            response.assign(buffer.begin(), buffer.begin() + bytesRead);
                                        }
                                    } else {
                                        response.assign(buffer.begin(), buffer.begin() + bytesRead);
                                    }
                                } else {
                                    response.assign(buffer.begin(), buffer.begin() + bytesRead);
                                }
                            } else {
                                response.assign(buffer.begin(), buffer.begin() + bytesRead);
                            }
                        } else {
                            response.assign(buffer.begin(), buffer.begin() + bytesRead);
                        }
                    } else {
                        response.assign(buffer.begin(), buffer.begin() + bytesRead);
                    }
                    break;
                }
                    
                case 2:
                    Log("SERVER", "Server list request - stopping VGC...", 12);
                    system("sc stop vgc >nul 2>&1");
                    response = CraftAuthResponseSimple(magic);
                    break;
                    
                case 4:
                {
                    bool wasSessionActive = g_SessionActive;
                    Log("AUTH", "Auth token packet - wasSessionActive=" + std::string(wasSessionActive ? "true" : "false"), 13);
                    Log("AUTH", "Auth token packet - extracting credentials...", 13);
                    std::vector<uint8_t> payload(buffer.begin(), buffer.begin() + bytesRead);
                    
                    std::string token, sid;
                    if (ExtractFromPacket(payload, token, sid)) {
                        if (!token.empty()) {
                            cachedToken = token;
                            {
                                std::lock_guard<std::mutex> lock(g_SessionMutex);
                                g_CachedToken = token;
                            }
                            Log("AUTH", "Token cached: " + token.substr(0, 50) + "...", 10);
                        }
                        if (!sid.empty()) {
                            cachedSid = sid;
                            {
                                std::lock_guard<std::mutex> lock(g_SessionMutex);
                                g_CachedSid = sid;
                            }
                            Log("AUTH", "SID cached: " + sid, 10);
                        }
                    } else {
                        Log("WARN", "Could not extract token/sid", 12);
                    }
                    
                    int protocolVersion = 4;
                    std::vector<uint8_t> uuidBytes;
                    std::string uuidStr;
                    std::regex uuidRegex(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
                    std::string payloadStr(payload.begin(), payload.end());
                    std::smatch match;
                    if (std::regex_search(payloadStr, match, uuidRegex)) {
                        uuidStr = match.str(0);
                        std::string cleanUUID = uuidStr;
                        cleanUUID.erase(std::remove(cleanUUID.begin(), cleanUUID.end(), '-'), cleanUUID.end());
                        for (size_t i = 0; i < cleanUUID.length() && i < 32; i += 2) {
                            if (i + 1 < cleanUUID.length()) {
                                std::string byteString = cleanUUID.substr(i, 2);
                                uint8_t byte = (uint8_t)strtol(byteString.c_str(), NULL, 16);
                                uuidBytes.push_back(byte);
                            }
                        }
                    }
                    
                    response = CraftAuthResponse(magic, protocolVersion, uuidBytes);
                    
                    Log("AUTH", "Auto-triggering gateway mint...", 10);
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    
                    if (!cachedToken.empty() && !cachedSid.empty()) {
                            Log("GATEWAY", "Sending to PHP relay...", 10);
                            std::string phpResponse;
                            if (PhpGatewayAuth(cachedToken, cachedSid, "valo", phpResponse)) {
                                Log("GATEWAY", "PHP auth response: " + phpResponse.substr(0, 80) + "...", 10);
                                
                                std::regex dataRegex(R"x("data"\s*:\s*"([^"]+)")x");
                                std::smatch dataMatch;
                                if (std::regex_search(phpResponse, dataMatch, dataRegex)) {
                                    std::string b64Data = dataMatch.str(1);
                                    std::vector<uint8_t> gwPayload = Base64Decode(b64Data);
                                    
                                    Log("GATEWAY", "Forwarding auth to Vanguard via PHP relay...", 10);
                                    std::string vgRespB64;
                                    if (PhpGatewayForward(b64Data, vgRespB64)) {
                                        Log("GATEWAY", "Forward raw response: " + vgRespB64.substr(0, 200), 10);
                                        
                                        std::smatch forwardMatch;
                                        if (std::regex_search(vgRespB64, forwardMatch, dataRegex)) {
                                            std::string vanguardResponseB64 = forwardMatch.str(1);
                                            std::vector<uint8_t> vanguardResponse = Base64Decode(vanguardResponseB64);
                                            
                                            Log("GATEWAY", "Sending Vanguard response to PHP for access step...", 10);
                                            std::string accessResponse;
                                            if (PhpGatewayAccess(vanguardResponseB64, accessResponse)) {
                                                Log("GATEWAY", "Access response: " + accessResponse.substr(0, 80) + "...", 10);
                                                std::smatch accessMatch;
                                                if (std::regex_search(accessResponse, accessMatch, dataRegex)) {
                                                    std::string accessB64 = accessMatch.str(1);
                                                    
                                                    Log("GATEWAY", "Forwarding access to Vanguard via PHP relay...", 10);
                                                    std::string finalResponseB64;
                                                    if (PhpGatewayForward(accessB64, finalResponseB64)) {
                                                        Log("GATEWAY", "Session established!", 10);
                                                        g_SessionActive = true;
                                                        
                                                        {
                                                            std::lock_guard<std::mutex> lock(g_SessionMutex);
                                                            g_SessionInitialized = true;
                                                        }
                                                    } else {
                                                        Log("GATEWAY", "Access forward failed", 12);
                                                    }
                                                } else {
                                                    Log("GATEWAY", "Failed to parse access response data", 12);
                                                }
                                            } else {
                                                Log("GATEWAY", "PHP access request failed", 12);
                                            }
                                        } else {
                                            Log("GATEWAY", "Failed to parse forward response data", 12);
                                        }
                                    } else {
                                        Log("GATEWAY", "PHP forward request failed", 12);
                                    }
                                } else {
                                    Log("GATEWAY", "Failed to parse PHP response data", 12);
                                }
                            } else {
                                Log("GATEWAY", "PHP relay request failed", 12);
                            }
                        }
                    break;
                }
                
                default:
                    response.assign(buffer.begin(), buffer.begin() + bytesRead);
                    break;
            }
            
            if (!response.empty()) {
                WriteFile(hPipe, response.data(), (DWORD)response.size(), &bytesWritten, NULL);
                Log("SEND", "Response dispatched (" + std::to_string(bytesWritten) + " bytes)", 14);
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    Log("C", "Connection closed", 12);
    CloseHandle(hPipe);
    g_PipeHandle = INVALID_HANDLE_VALUE;
}

void PipeServer() {
    while (!g_Shutdown) {
        HANDLE hPipe = CreateNamedPipeW(
            VANGUARD_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            1,
            0x100000,
            0x100000,
            500,
            NULL
        );
        
        if (hPipe == INVALID_HANDLE_VALUE) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        
        Log("P", "Named pipe created - awaiting client...", 13);
        
        if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
            std::thread(ClientHandler, hPipe).detach();
        } else {
            CloseHandle(hPipe);
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void StartPhpServer() {
    if (g_PhpServerRunning) return;
    
    Log("PHP", "Killing existing PHP processes...", 12);
    system("taskkill /f /im php.exe >nul 2>&1");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    Log("PHP", "Starting PHP built-in server on port 8089...", 11);
    
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string exeDir = exePath;
    size_t lastSlash = exeDir.rfind('\\');
    if (lastSlash != std::string::npos) {
        exeDir = exeDir.substr(0, lastSlash);
    }
    
    std::string cmd = "php -S 127.0.0.1:8089 -t \"" + exeDir + "\" > php_server.log 2>&1";
    
    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, exeDir.c_str(), &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        g_PhpServerRunning = true;
        Log("PHP", "PHP server started successfully", 10);
        
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        FILE* f = fopen("php_server.log", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "listening") || strstr(line, "Server started")) {
                    Log("PHP", "PHP server is ready", 10);
                    break;
                }
            }
            fclose(f);
        }
    } else {
        Log("PHP", "Failed to start PHP server", 12);
    }
}

void ProcessMonitor() {
    Log("INFO", "Waiting for Valorant to launch...", 11);
    while (!g_Shutdown) {
        system("sc stop vgc >nul 2>&1");
        if (!g_VgcStoppedLogged) {
            Log("INFO", "VGC stopped - safe to inject", 12);
            g_VgcStoppedLogged = true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    if (_wcsicmp(pe32.szExeFile, VALORANT_EXE_NAME) == 0) {
                        Log("INFO", "Valorant detected!", 10);
                        StartPhpServer();
                        goto end_monitor;
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
end_monitor:;
}

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        g_Shutdown = true;
        return TRUE;
    }
    return FALSE;
}

int main() {
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);
    
    std::cout << "========================================" << std::endl;
    std::cout << "   VGC EMULATOR + SESSION MAKER (NOREST)" << std::endl;
    std::cout << "========================================" << std::endl;
    
    Log("INIT", "Stopping VGC service...", 14);
    system("sc stop vgc >nul 2>&1");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    Log("INIT", "Starting VGC service...", 10);
    system("sc start vgc >nul 2>&1");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    BlockRiotTelemetry();
    
    FILE* lf = fopen(LOG_FILE, "w");
    if (lf) fclose(lf);
    
    Log("INIT", "Pipe server starting...", 10);
    std::thread pipeThread(PipeServer);
    
    ProcessMonitor();
    
    Log("MAIN", "Valorant detected, emulator running. Press Ctrl+C to stop.", 10);
    
    while (!g_Shutdown) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    Log("MAIN", "Shutting down...", 14);
    UnblockRiotTelemetry();
    
    if (pipeThread.joinable()) {
        pipeThread.join();
    }
    Log("MAIN", "Exiting...", 10);
    return 0;
}
