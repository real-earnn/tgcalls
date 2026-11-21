#include "LogSinkImpl.h"

#include "Instance.h"

#ifdef WEBRTC_WIN
#include "windows.h"
#include <ctime>
#else // WEBRTC_WIN
#include <sys/time.h>
#endif // WEBRTC_WIN

namespace tgcalls {

LogSinkImpl::LogSinkImpl(const FilePath &logPath) {
	if (!logPath.data.empty()) {
		_file.open(logPath.data);
	}
}

void LogSinkImpl::OnLogMessage(const std::string &msg, rtc::LoggingSeverity severity, const char *tag) {
	OnLogMessage(std::string(tag) + ": " + msg);
}

void LogSinkImpl::OnLogMessage(const std::string &message, rtc::LoggingSeverity severity) {
	OnLogMessage(message);
}

void LogSinkImpl::OnLogMessage(const std::string &message) {
	time_t rawTime;
	time(&rawTime);
	struct tm timeinfo;

#ifdef WEBRTC_WIN
	localtime_s(&timeinfo, &rawTime);

	FILETIME ft;
	unsigned __int64 full = 0;
	GetSystemTimeAsFileTime(&ft);

	full |= ft.dwHighDateTime;
	full <<= 32;
	full |= ft.dwLowDateTime;

	const auto deltaEpochInMicrosecs = 11644473600000000Ui64;
	full -= deltaEpochInMicrosecs;
	full /= 10;
	int32_t milliseconds = (long)(full % 1000000UL) / 1000;
#else
	timeval curTime = { 0 };
	localtime_r(&rawTime, &timeinfo);
	gettimeofday(&curTime, nullptr);
	int32_t milliseconds = curTime.tv_usec / 1000;
#endif

	// SilentGram: tee every line into _data as well as the file, so
	// result() (FinalState.debugLog) actually contains the RTC log.
	// Upstream wrote to exactly one of them: with a logPath set, the log
	// went to the file only and result() was always empty, so Java never
	// saw the SG-UDP markers (VoIPService scanned an empty debugLog).
	// _data is capped: the markers are emitted at call start, so the head
	// of the log is what Java needs; the file keeps the full log.
	std::ostringstream line;
	line
		<< (timeinfo.tm_year + 1900)
		<< "-" << (timeinfo.tm_mon + 1)
		<< "-" << (timeinfo.tm_mday)
		<< " " << timeinfo.tm_hour
		<< ":" << timeinfo.tm_min
		<< ":" << timeinfo.tm_sec
		<< ":" << milliseconds
		<< " " << message;
	if (_file.is_open()) {
		_file << line.str();
	}
	if (_data.tellp() < kMaxDataBytes) {
		_data << line.str();
	}

#if DEBUG
    printf("%d-%d-%d %d:%d:%d:%d %s\n", timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday, timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec, milliseconds, message.c_str());
#endif
}

} // namespace tgcalls
