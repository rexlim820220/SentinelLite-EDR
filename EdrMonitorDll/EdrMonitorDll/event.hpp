#pragma once
#include <string>
#include <chrono>
#include <sstream>
#include <iomanip>

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

struct SecurityEvent {
	std::chrono::system_clock::time_point timestamp;
	uint32_t process_id;
	std::wstring process_name;
	ApiType api_called;
	Severity severity;
	std::wstring details;

	SecurityEvent()
		: timestamp(std::chrono::system_clock::now()),
		  process_id(0),
		  severity(Severity::Info),
		  api_called(ApiType::VirtualAllocEx) {}

	SecurityEvent(SecurityEvent&& rhs) noexcept
		: timestamp(rhs.timestamp),
		  process_id(rhs.process_id),
		  process_name(std::move(rhs.process_name)),
		  api_called(rhs.api_called),
		  severity(rhs.severity),
		  details(std::move(rhs.details)) {}

	SecurityEvent(const SecurityEvent&) = default;
	SecurityEvent& operator=(const SecurityEvent&) = default;
	SecurityEvent& operator=(SecurityEvent&&) = default;
};