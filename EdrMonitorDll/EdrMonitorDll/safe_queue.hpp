#pragma once
#include "event.hpp"
#include <queue>
#include <mutex>
#include <chrono>
#include <cstddef>
#include <condition_variable>

class ThreadSafeQueue {
private:
	std::queue<SecurityEvent> m_queue;
	mutable std::mutex        m_mutex;
	std::condition_variable   m_cv_pop;
	const size_t              m_max_size;
	bool                      m_shutdown;

public:
	explicit ThreadSafeQueue(size_t max_size = 1000)
		: m_max_size(max_size), m_shutdown(false) {}

		~ThreadSafeQueue() {
		Shutdown();
	}

	ThreadSafeQueue(const ThreadSafeQueue&)            = delete;
	ThreadSafeQueue& operator=(const ThreadSafeQueue&) = delete;

	bool Push(SecurityEvent&& event) {
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			if (m_shutdown || m_queue.size() >= m_max_size)
				return false;
			m_queue.push(std::move(event));
		}
		m_cv_pop.notify_one();
		return true;
	}

	bool Pop(SecurityEvent& event, std::chrono::milliseconds timeout) {
		std::unique_lock<std::mutex> lock(m_mutex);
		m_cv_pop.wait_for(lock, timeout, [this]() {
			return !m_queue.empty() || m_shutdown;
		});

		if (m_queue.empty()) {
			return false;
		}

		event = std::move(m_queue.front());
		m_queue.pop();

		return true;
	}

	void Shutdown() {
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			m_shutdown = true;
		}
		m_cv_pop.notify_all();
	}

	[[nodiscard]] size_t Size() const {
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_queue.size();
	}

	[[nodiscard]] bool IsShutdown() const {
		std::lock_guard<std::mutex> lock(m_mutex);
		return m_shutdown;
	}
};