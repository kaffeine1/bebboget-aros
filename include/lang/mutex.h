/*
 * javalike Mutex interface
 * Copyright (C) 1998-2012, 2024-2025  Stefan Franke <stefan@franke.ms>
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
 * Purpose: Provide mutex and scoped lock classes for synchronization
 *          within the javalike library.
 *
 * Features:
 *  - Mutex class with obtain/release methods
 *  - MutexLock RAII helper for scoped locking
 *  - Macros for synchronized blocks
 *
 * Notes:
 *  - Copying of Mutex and MutexLock is explicitly disabled using = delete
 *  - Contributions must preserve author attribution and GPL licensing
 * ----------------------------------------------------------------------
 */

#ifndef __LANG_MUTEX_H__
#define __LANG_MUTEX_H__

namespace lang {

    /**
     * @class Mutex
     * @brief Provides mutual exclusion for synchronization.
     */
    class Mutex {
    public:
        Mutex(Mutex const&) = delete;
        Mutex& operator=(Mutex const&) = delete;

    private:
        void* data;

    public:
        Mutex();
        ~Mutex();

        /// Acquire the mutex, with optional timeout
        void obtain(unsigned int timeout = 0xffffffffL);

        /// Release the mutex
        void release();
    };

    /**
     * @class MutexLock
     * @brief Scoped lock helper for Mutex.
     *
     * Acquires a mutex on construction and releases it on destruction.
     */
    class MutexLock {
    public:
        MutexLock(MutexLock const&) = delete;
        MutexLock& operator=(MutexLock const&) = delete;

    private:
        Mutex* mutex;

    public:
        inline MutexLock(Mutex& m) : mutex(0) {
            m.obtain();
            mutex = &m;
        }
        inline ~MutexLock() {
            if (mutex) mutex->release();
        }
    };

    /// Macro for synchronized block using a Mutex reference
    #define synchronized(lock) MutexLock lock##__LINE__(lock)

    /// Macro for synchronized block using a Mutex pointer
    #define synchronizedp(lock) MutexLock lock##__LINE__(*lock)

} // namespace lang

#endif // __LANG_MUTEX_H__
