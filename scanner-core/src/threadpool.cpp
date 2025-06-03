/**
 * @file threadpool.cpp
 * @brief Implements the ThreadPool class for managing concurrent task execution.
 *
 * This file contains the implementation of the ThreadPool, which manages a set of worker threads
 * to execute tasks concurrently. Tasks are enqueued and processed by available threads.
 * The thread pool provides thread-safe task management and ensures proper cleanup on shutdown.
 *
 * Features:
 * - Creation and management of worker threads.
 * - Thread-safe task queue.
 * - Graceful shutdown and joining of threads.
 *
 * @author Dorna Raj Gyawali <dronarajgyawali@gmail.com>
 * @date 2025
 */

#include "threadpool.h"

ThreadPool::ThreadPool(size_t threads) : stop(false) {
    for (size_t i = 0; i < threads; ++i) {
        workers.emplace_back([this] {
            for (;;) {
                std::function<void()> task;

                {
                    std::unique_lock<std::mutex> lock(this->queue_mutex);
                    this->condition.wait(lock, [this] { return this->stop || !this->tasks.empty(); });
                    if (this->stop && this->tasks.empty())
                        return;
                    task = std::move(this->tasks.front());
                    this->tasks.pop();
                }

                task();
            }
        });
    }
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        stop = true;
    }
    condition.notify_all();
    for (std::thread &worker : workers)
        worker.join();
}
