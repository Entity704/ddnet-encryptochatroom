if(WIN32)
  set(CRYPTO_FOUND ON)
  set(CRYPTO_BUNDLED OFF)

  if(MSVC)
    set(CRYPTO_INCLUDEDIR "C:/vcpkg/installed/x64-windows/include")
    set(CRYPTO_LIBRARY "C:/vcpkg/installed/x64-windows/lib/libcrypto.lib" "C:/vcpkg/installed/x64-windows/lib/libssl.lib")
  else()
    set(CRYPTO_INCLUDEDIR "C:/vcpkg/installed/x64-mingw-dynamic/include")
    set(CRYPTO_LIBRARY "C:/vpkg/installed/x64-mingw-dynamic/lib/libcrypto.dll.a" "C:/vcpkg/installed/x64-mingw-dynamic/lib/libssl.dll.a")
  endif()

else()
  if(NOT PREFER_BUNDLED_LIBS)
    find_package(OpenSSL)
    if(OPENSSL_FOUND)
      set(CRYPTO_FOUND ON)
      set(CRYPTO_BUNDLED OFF)
      if(OPENSSL_CRYPTO_LIBRARY)
        set(CRYPTO_LIBRARY ${OPENSSL_CRYPTO_LIBRARY})
      else()
        set(CRYPTO_LIBRARY ${OPENSSL_CRYPTO_LIBRARIES})
      endif()
      set(CRYPTO_INCLUDEDIR ${OPENSSL_INCLUDE_DIR})
    endif()
  endif()

  if(PREFER_BUNDLED_LIBS AND TARGET_OS STREQUAL "android")
    set_extra_dirs_lib(CRYPTO boringssl)
    find_library(CRYPTO_LIBRARY
      NAMES crypto
      HINTS ${HINTS_CRYPTO_LIBDIR} ${PC_CRYPTO_LIBDIR} ${PC_CRYPTO_LIBRARY_DIRS}
      PATHS ${PATHS_CRYPTO_LIBDIR}
      ${CROSSCOMPILING_NO_CMAKE_SYSTEM_PATH}
    )
    find_library(SSL_LIBRARY
      NAMES ssl
      HINTS ${HINTS_CRYPTO_LIBDIR} ${PC_CRYPTO_LIBDIR} ${PC_CRYPTO_LIBRARY_DIRS}
      PATHS ${PATHS_CRYPTO_LIBDIR}
      ${CROSSCOMPILING_NO_CMAKE_SYSTEM_PATH}
    )
    set(CRYPTO_LIBRARY ${CRYPTO_LIBRARY} ${SSL_LIBRARY})

    set(CMAKE_FIND_FRAMEWORK FIRST)
    set_extra_dirs_include(CRYPTO boringssl "${CRYPTO_LIBRARY}")
    find_path(CRYPTO_INCLUDEDIR openssl/ssl.h openssl/base.h openssl/hkdf.h openssl/opensslconf.h
      PATH_SUFFIXES CRYPTO
      HINTS ${HINTS_CRYPTO_INCLUDEDIR} ${PC_CRYPTO_INCLUDEDIR} ${PC_CRYPTO_INCLUDE_DIRS}
      PATHS ${PATHS_CRYPTO_INCLUDEDIR}
      ${CROSSCOMPILING_NO_CMAKE_SYSTEM_PATH}
    )
  endif()
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Crypto DEFAULT_MSG CRYPTO_LIBRARY CRYPTO_INCLUDEDIR)

mark_as_advanced(CRYPTO_LIBRARY CRYPTO_INCLUDEDIR)

if(CRYPTO_FOUND)
  set(CRYPTO_LIBRARIES ${CRYPTO_LIBRARY})
  set(CRYPTO_INCLUDE_DIRS ${CRYPTO_INCLUDEDIR})
endif()
