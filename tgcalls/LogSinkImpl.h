#ifndef TGCALLS_LOG_SINK_IMPL_H
#define TGCALLS_LOG_SINK_IMPL_H

#include "rtc_base/logging.h"
#include <fstream>
#include <sstream>

namespace tgcalls {

struct FilePath;

class LogSinkImpl final : public rtc::LogSink {
public:
	LogSinkImpl(const FilePath &logPath);

	void OnLogMessage(const std::string &msg, rtc::LoggingSeverity severity, const char *tag) override;
	void OnLogMessage(const std::string &message, rtc::LoggingSeverity severity) override;
	void OnLogMessage(const std::string &message) override;

	std::string result() const {
		return _data.str();
	}

private:
	// SilentGram: cap for the in-memory tee (see LogSinkImpl.cpp).
	// 4 MiB bounds RAM on long calls; markers are emitted at call
	// start, so the head of the log is what result() must carry.
	static constexpr std::streamsize kMaxDataBytes = 4 * 1024 * 1024;

	std::ofstream _file;
	std::ostringstream _data;

};

} // namespace tgcalls

#endif
