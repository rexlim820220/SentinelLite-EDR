#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <optional>
#include <windows.h>

enum class Severity : uint8_t {
	Info,
	Warning,
	Critical
};

enum class ApiType : uint8_t {
	VirtualAllocEx,
	CreateRemoteThread,
	RegSetValueEx
};

inline const char* SeverityToStr(Severity s) noexcept {
    switch (s) {
        case Severity::Info:     return "INFO";
        case Severity::Warning:  return "WARNING";
        case Severity::Critical: return "CRITICAL";
        default:                 return "UNKNOWN";
    }
}

inline const char* ApiTypeToStr(ApiType a) noexcept {
    switch (a) {
        case ApiType::VirtualAllocEx:     return "VirtualAllocEx";
        case ApiType::CreateRemoteThread: return "CreateRemoteThread";
        case ApiType::RegSetValueEx:      return "RegSetValueEx";
        default:                          return "Unknown";
    }
}

inline std::string WstrToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int size_needed = WideCharToMultiByte(
        CP_UTF8, 0,
        wstr.c_str(), static_cast<int>(wstr.size()),
        nullptr, 0,
        nullptr, nullptr);
    if (size_needed <= 0) return {};
    std::string result(size_needed, '\0');
    WideCharToMultiByte(
        CP_UTF8, 0,
        wstr.c_str(), static_cast<int>(wstr.size()),
        result.data(), size_needed,
        nullptr, nullptr);
    return result;
}

inline std::wstring Utf8ToWstr(const std::string& str) {
    if (str.empty()) return {};
    int size_needed = MultiByteToWideChar(
        CP_UTF8, 0,
        str.c_str(), static_cast<int>(str.size()),
        nullptr, 0);
    if (size_needed <= 0) return {};
    std::wstring result(size_needed, L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0,
        str.c_str(), static_cast<int>(str.size()),
        result.data(), size_needed);
    return result;
}

struct SecurityEvent {
	std::chrono::system_clock::time_point timestamp;
	uint32_t     process_id;
	std::wstring process_name;
	ApiType      api_called;
	Severity     severity;
	std::wstring details;

	SecurityEvent()
		: timestamp(std::chrono::system_clock::now()),
		  process_id(0),
		  severity(Severity::Info),
		  api_called(ApiType::VirtualAllocEx) {}

	SecurityEvent(uint32_t         pid,
                  std::wstring     name,
                  ApiType          api,
                  Severity         sev,
                  std::wstring     det)
        : timestamp(std::chrono::system_clock::now())
        , process_id(pid)
        , process_name(std::move(name))
        , api_called(api)
        , severity(sev)
        , details(std::move(det))
	{}

	SecurityEvent(SecurityEvent&& rhs) noexcept
		: timestamp(rhs.timestamp),
		  process_id(rhs.process_id),
		  process_name(std::move(rhs.process_name)),
		  api_called(rhs.api_called),
		  severity(rhs.severity),
		  details(std::move(rhs.details)) {}

	SecurityEvent& operator=(SecurityEvent&& rhs) noexcept {
        if (this != &rhs) {
            timestamp    = rhs.timestamp;
            process_id   = rhs.process_id;
            process_name = std::move(rhs.process_name);
            api_called   = rhs.api_called;
            severity     = rhs.severity;
            details      = std::move(rhs.details);
        }
        return *this;
    }

	SecurityEvent(const SecurityEvent&) = delete;
	SecurityEvent& operator=(const SecurityEvent&) = delete;

	// ── Convert to text lines for Pipe transmission ─────────────────
	[[nodiscard]] std::string Serialize() const {
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()
        ).count();

        std::ostringstream oss;
        oss << ms                               // [0] timestamp
            << '|' << process_id                // [1] PID
            << '|' << SeverityToStr(severity)   // [2] severity string
            << '|' << ApiTypeToStr(api_called)  // [3] API name
            << '|' << WstrToUtf8(process_name)  // [4] process name
            << '|' << WstrToUtf8(details)       // [5] details
            << '\n';                            // readline 分隔符

        return oss.str();
    }

	// The controller reads from the pipe and then restores it (static factory)
	static std::optional<SecurityEvent> Deserialize(const std::string& line) {
        std::vector<std::string> parts;
        std::istringstream ss(line);
        std::string token;
        while (std::getline(ss, token, '|')) {
            parts.push_back(token);
        }
        if (parts.size() < 6) return std::nullopt;

        SecurityEvent ev;

        // [0] timestamp
        try {
            long long ms = std::stoll(parts[0]);
            ev.timestamp = std::chrono::system_clock::time_point(
                std::chrono::milliseconds(ms)
            );
        } catch (...) { return std::nullopt; }

        // [1] PID
        try { ev.process_id = static_cast<uint32_t>(std::stoul(parts[1])); }
        catch (...) { return std::nullopt; }

        // [2] Severity
        if      (parts[2] == "INFO")     ev.severity = Severity::Info;
        else if (parts[2] == "WARNING")  ev.severity = Severity::Warning;
        else if (parts[2] == "CRITICAL") ev.severity = Severity::Critical;
        else return std::nullopt;

        // [3] ApiType
        if      (parts[3] == "VirtualAllocEx")      ev.api_called = ApiType::VirtualAllocEx;
        else if (parts[3] == "CreateRemoteThread")  ev.api_called = ApiType::CreateRemoteThread;
        else if (parts[3] == "RegSetValueEx")       ev.api_called = ApiType::RegSetValueEx;
        else return std::nullopt;

        ev.process_name = Utf8ToWstr(parts[4]);

        std::string det = parts[5];
        if (!det.empty() && det.back() == '\r') det.pop_back();
        ev.details = std::wstring(det.begin(), det.end());

        return ev;
    }
};