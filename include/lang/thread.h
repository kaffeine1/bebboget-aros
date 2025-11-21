/*
 * javalike Thread interface
 * Copyright (C) 2008-2011, 2024-2025  Stefan Franke <stefan@franke.ms>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version (GPLv3+).
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * ----------------------------------------------------------------------
 * Project: javalike
 * Purpose: Provide abstract thread interface for concurrent execution
 *          within the javalike library.
 *
 * Features:
 *  - Abstract Thread class with start() and run() methods
 *  - launchThread helper for platform-specific thread creation
 *  - Prevents copying of Thread objects
 *
 * Notes:
 *  - Derived classes must implement run()
 *  - Copying is disabled using = delete
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __LANG_THREAD_H__
#define __LANG_THREAD_H__

namespace lang {

struct ThreadData;

/**
 * @class Thread
 * @brief Abstract thread interface.
 *
 * Provides a base class for creating threads. Derived classes
 * must implement the run() method. Threads are started with start().
 */
class Thread {
public:
    Thread(Thread const&) = delete;
    Thread& operator=(Thread const&) = delete;

private:
    ThreadData* data;

    /// Internal helper to launch a thread
    static void launchThread(Thread*);

protected:
    /// Protected constructor for derived classes
    Thread();

    /// Method executed in thread context (must be implemented by subclass)
    virtual void run() = 0;

public:
    /// Virtual destructor
    virtual ~Thread();

    /// Start the thread
    void start();
};

} // namespace lang

#endif /* __LANG_THREAD_H__ */
