# Copyright (c) 2014 Alexander Lamaison <alexander.lamaison@gmail.com>
#
# Redistribution and use in source and binary forms,
# with or without modification, are permitted provided
# that the following conditions are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the following
#   disclaimer in the documentation and/or other materials
#   provided with the distribution.
#
#   Neither the name of the copyright holder nor the names
#   of any other contributors may be used to endorse or
#   promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
# CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
# OF SUCH DAMAGE.

include(CheckFunctionExists)
include(CheckFunctionExistsMayNeedLibrary)
include(CheckIncludeFiles)
include(CheckTypeSize)
include(CheckNonblockingSocketSupport)

## Options

add_feature_info("Shared library" BUILD_SHARED_LIBS
  "creating libssh2 as a shared library (.so/.dll)")

option(ENABLE_ZLIB_COMPRESSION "Use zlib for compression")
add_feature_info(Compression ENABLE_ZLIB_COMPRESSION
  "using zlib for compression")
if(ENABLE_ZLIB_COMPRESSION)
  find_package(ZLIB REQUIRED)

  include_directories(${ZLIB_INCLUDE_DIRS})
  list(APPEND LIBRARIES ${ZLIB_LIBRARIES})
  if(ZLIB_FOUND)
    add_definitions(-DLIBSSH2_HAVE_ZLIB=1)
  endif()
endif()

option(ENABLE_CRYPT_NONE "Permit \"none\" cipher -- NOT RECOMMENDED")
add_feature_info("\"none\" cipher" ENABLE_CRYPT_NONE "")
if(ENABLE_CRYPT_NONE)
  add_definitions(-DLIBSSH2_CRYPT_NONE=1)
endif()

option(ENABLE_MAC_NONE "Permit \"none\" MAC -- NOT RECOMMMENDED")
add_feature_info("\"none\" MAC" ENABLE_MAC_NONE "")
if(ENABLE_MAC_NONE)
  add_definitions(-DLIBSSH2_MAC_NONE=1)
endif()

option(ENABLE_GEX_NEW
  "Enable diffie-hellman-group-exchange-sha1 method" ON)
add_feature_info("diffie-hellman-group-exchange-sha1" ENABLE_GEX_NEW
  "\"new\" diffie-hellman-group-exchange-sha1 method")
if(ENABLE_GEX_NEW)
  add_definitions(-DLIBSSH2_DH_GEX_NEW=1)
endif()

# Enable debugging logging by default if the user configured a debug build
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(DEBUG_LOGGING_DEFAULT ON)
else()
  set(DEBUG_LOGGING_DEFAULT OFF)
endif()
option(ENABLE_DEBUG_LOGGING "log execution with debug trace"
  ${DEBUG_LOGGING_DEFAULT})
add_feature_info(Logging ENABLE_DEBUG_LOGGING
   "Logging of execution with debug trace")
if(ENABLE_DEBUG_LOGGING)
  add_definitions(-DLIBSSH2DEBUG)
endif()

## Cryptography backend choice

set(CRYPTO_BACKEND
  ""
  CACHE
  STRING
  "The backend to use for cryptography: OpenSSL, Libgcrypt or WinCNG,
or empty to try any available")

# If the crypto backend was given, rather than searching for the first
# we are able to find, the find_package commands must abort configuration
# and report to the user.
if(CRYPTO_BACKEND)
  set(SPECIFIC_CRYPTO_REQUIREMENT REQUIRED)
endif()

if(CRYPTO_BACKEND STREQUAL "OpenSSL" OR NOT CRYPTO_BACKEND)

  find_package(OpenSSL ${SPECIFIC_CRYPTO_REQUIREMENT})

  if(OPENSSL_FOUND)
    set(CRYPTO_BACKEND "OpenSSL")
    set(CRYPTO_SOURCES openssl.c openssl.h)
    add_definitions(-DLIBSSH2_OPENSSL)

    include_directories(${OPENSSL_INCLUDE_DIR})
    list(APPEND LIBRARIES ${OPENSSL_LIBRARIES})

    if (WIN32)
      find_file(DLL_LIBEAY32
	NAMES libeay32.dll crypto.dll
        HINTS ${_OPENSSL_ROOT_HINTS} PATHS ${_OPENSSL_ROOT_PATHS}
        PATH_SUFFIXES bin)
      if (NOT DLL_LIBEAY32)
        message(WARNING
          "Unable to find OpenSSL libeay32 DLL, executables may not run")
      endif()

      find_file(DLL_SSLEAY32
        NAMES ssleay32.dll ssl.dll
        HINTS ${_OPENSSL_ROOT_HINTS} PATHS ${_OPENSSL_ROOT_PATHS}
        PATH_SUFFIXES bin)
      if (NOT DLL_SSLEAY32)
        message(WARNING
          "Unable to find OpenSSL ssleay32 DLL, executables may not run")
      endif()

      if(DLL_LIBEAY32 AND DLL_SSLEAY32)
        list(APPEND _RUNTIME_DEPENDENCIES ${DLL_LIBEAY32} ${DLL_SSLEAY32})
      endif()
    endif()

    # Not all OpenSSL have AES-CTR functions.
    set(SAVE_CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
    set(CMAKE_REQUIRED_LIBRARIES ${OPENSSL_LIBRARIES})
    check_function_exists(EVP_aes_128_ctr HAVE_EVP_AES_128_CTR)
    set(CMAKE_REQUIRED_LIBRARIES ${SAVE_CMAKE_REQUIRED_LIBRARIES})
  endif()
endif()

if(CRYPTO_BACKEND STREQUAL "Libgcrypt" OR NOT CRYPTO_BACKEND)

  find_package(Libgcrypt ${SPECIFIC_CRYPTO_REQUIREMENT})

  if(LIBGCRYPT_FOUND)
    set(CRYPTO_BACKEND "Libgcrypt")
    set(CRYPTO_SOURCES libgcrypt.c libgcrypt.h)
    add_definitions(-DLIBSSH2_LIBGCRYPT)

    include_directories(${LIBGCRYPT_INCLUDE_DIRS})
    list(APPEND LIBRARIES ${LIBGCRYPT_LIBRARIES})
  endif()
endif()

if(CRYPTO_BACKEND STREQUAL "WinCNG" OR NOT CRYPTO_BACKEND)

  # The check actually compiles the header.  This requires windows.h.
  check_include_files("windows.h;bcrypt.h" HAVE_BCRYPT_H)

  if(HAVE_BCRYPT_H)
    set(CRYPTO_BACKEND "WinCNG")
    set(CRYPTO_SOURCES wincng.c wincng.h)
    add_definitions(-DLIBSSH2_WINCNG)

    set(HAVE_LIBCRYPT32 TRUE)
    list(APPEND LIBRARIES bcrypt)

    check_include_files(ntdef.h HAVE_NTDEF_H)
    check_include_files(ntstatus.h HAVE_NTSTATUS_H)

    # Reading keys from files is optional and depends on Wincrypt
    check_include_files("windows.h;wincrypt.h" HAVE_WINCRYPT_H)

    if(HAVE_WINCRYPT_H)
      list(APPEND LIBRARIES crypt32)
    endif()

  elseif(${SPECIFIC_CRYPTO_REQUIREMENT} STREQUAL ${REQUIRED})
    message(FATAL_ERROR "WinCNG not available")
  endif()
endif()

if(NOT CRYPTO_BACKEND)
  message(FATAL_ERROR "No suitable cryptography backend found.")
endif()

## Platform checks
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files(inttypes.h HAVE_INTTYPES_H)
check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(sys/select.h HAVE_SYS_SELECT_H)

check_include_files(sys/uio.h HAVE_SYS_UIO_H)
check_include_files(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_files(sys/ioctl.h HAVE_SYS_IOCTL_H)
check_include_files(sys/time.h HAVE_SYS_TIME_H)
check_include_files(sys/un.h HAVE_SYS_UN_H)
check_include_files(windows.h HAVE_WINDOWS_H)
check_include_files(ws2tcpip.h HAVE_WS2TCPIP_H)
check_include_files(winsock2.h HAVE_WINSOCK2_H)

check_type_size("long long" LONGLONG)

check_function_exists(gettimeofday HAVE_GETTIMEOFDAY)
check_function_exists(strtoll HAVE_STRTOLL)
check_function_exists(snprintf HAVE_SNPRINTF)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin" OR
   ${CMAKE_SYSTEM_NAME} STREQUAL "Interix")
  # poll() does not work on these platforms
  #
  # Interix: "does provide poll(), but the implementing developer must
  # have been in a bad mood, because poll() only works on the /proc
  # filesystem here"
  #
  # Mac OS X's poll has funny behaviors, like:
  # not being able to do poll on no fildescriptors (10.3?)
  # not being able to poll on some files (like anything in /dev)
  # not having reliable timeout support
  # inconsistent return of POLLHUP where other implementations give POLLIN
  message("poll use is disabled on this platform")
else()
  check_function_exists(poll HAVE_POLL)
endif()

# Some systems have socket function in a library
# (Solaris -lsocket/-lnsl, Windows -lws2_32)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND CMAKE_SIZEOF_VOID_P EQUAL 4)
  # x86 Windows uses STDCALL for these functions, so their names are mangled,
  # meaning the platform checks don't work. Hardcoding these until we get
  # a better solution.
  set(HAVE_SOCKET 1)
  set(HAVE_SELECT 1)
  set(HAVE_INET_ADDR 1)
  set(NEED_LIB_WS2_32 1)
else()
  check_function_exists_may_need_library(socket HAVE_SOCKET socket ws2_32)
  check_function_exists_may_need_library(select HAVE_SELECT ws2_32)
  check_function_exists_may_need_library(inet_addr HAVE_INET_ADDR nsl ws2_32)
endif()

if(NEED_LIB_SOCKET)
  list(APPEND LIBRARIES socket)
endif()
if(NEED_LIB_NSL)
  list(APPEND LIBRARIES nsl)
endif()
if(NEED_LIB_WS2_32)
  list(APPEND LIBRARIES ws2_32)
endif()

# Non-blocking socket support tests.  Must be after after library tests to
# link correctly
set(SAVE_CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
set(CMAKE_REQUIRED_LIBRARIES ${LIBRARIES})
check_nonblocking_socket_support()
set(CMAKE_REQUIRED_LIBRARIES ${SAVE_CMAKE_REQUIRED_LIBRARIES})

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/libssh2_config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/libssh2_config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR}) # to find generated header

# Check for the OS.
# Daniel's note: this should not be necessary and we need to work to
# get this removed.
if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  add_definitions(-DLIBSSH2_WIN32)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
  add_definitions(-DLIBSSH2_DARWIN)
endif()

## Library definition

set(SOURCES
  ${CRYPTO_SOURCES}
  agent.c
  channel.c
  channel.h
  comp.c
  comp.h
  crypt.c
  crypto.h
  global.c
  hostkey.c
  keepalive.c
  kex.c
  knownhost.c
  libssh2_priv.h
  mac.c
  mac.h
  misc.c
  misc.h
  packet.c
  packet.h
  pem.c
  publickey.c
  scp.c
  session.c
  session.h
  sftp.c
  sftp.h
  transport.c
  transport.h
  userauth.c
  userauth.h
  version.c)

add_library(ssh2 ${SOURCES})
target_link_libraries(ssh2 ${LIBRARIES})

install(TARGETS ssh2
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib)

if(BUILD_SHARED_LIBS)
  list(APPEND _RUNTIME_DEPENDENCIES $<TARGET_FILE:ssh2>)
endif()

set(RUNTIME_DEPENDENCIES ${_RUNTIME_DEPENDENCIES} CACHE INTERNAL
    "Files that must be in the same directory as the executables at runtime.")
