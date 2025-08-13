# This file is indended to be included in end-user CMakeLists.txt
# include(/path/to/Filelists.cmake)
# It assumes the variable LWIP_CONTRIB_DIR is defined pointing to the
# root path of lwIP/contrib sources.
#
# This file is NOT designed (on purpose) to be used as cmake
# subdir via add_subdirectory()
# The intention is to provide greater flexibility to users to
# create their own targets using the *_SRCS variables.

if(NOT ${CMAKE_VERSION} VERSION_LESS "3.10.0")
    include_guard(GLOBAL)
endif()

set(lwipcontribportunix_SRCS
    ${LWIP_CONTRIB_DIR}/ports/unix/port/sys_arch.c
    ${LWIP_CONTRIB_DIR}/ports/unix/port/perf.c
)

set(lwipcontribportunixnetifs_SRCS
    ${LWIP_CONTRIB_DIR}/ports/unix/port/netif/tapif.c
    ${LWIP_CONTRIB_DIR}/ports/unix/port/netif/list.c
    ${LWIP_CONTRIB_DIR}/ports/unix/port/netif/sio.c
    ${LWIP_CONTRIB_DIR}/ports/unix/port/netif/fifo.c
)

add_library(lwipcontribportunix EXCLUDE_FROM_ALL ${lwipcontribportunix_SRCS} ${lwipcontribportunixnetifs_SRCS})

# Set basic include directories and definitions
set(CONTRIB_INCLUDE_DIRS ${LWIP_INCLUDE_DIRS})
set(CONTRIB_DEFINITIONS ${LWIP_DEFINITIONS})
set(CONTRIB_LINK_LIBRARIES "")

# Add TLS backend specific configurations
if(LWIP_HAVE_MBEDTLS)
    list(APPEND CONTRIB_INCLUDE_DIRS ${LWIP_MBEDTLS_INCLUDE_DIRS})
    list(APPEND CONTRIB_DEFINITIONS ${LWIP_MBEDTLS_DEFINITIONS})
    list(APPEND CONTRIB_LINK_LIBRARIES ${LWIP_MBEDTLS_LINK_LIBRARIES})
endif()

if(LWIP_HAVE_OPENHITLS)
    list(APPEND CONTRIB_INCLUDE_DIRS ${LWIP_OPENHITLS_INCLUDE_DIRS})
    list(APPEND CONTRIB_DEFINITIONS ${LWIP_OPENHITLS_DEFINITIONS})
    list(APPEND CONTRIB_LINK_LIBRARIES ${LWIP_OPENHITLS_LINK_LIBRARIES})
endif()

target_include_directories(lwipcontribportunix PRIVATE ${CONTRIB_INCLUDE_DIRS})
target_compile_options(lwipcontribportunix PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwipcontribportunix PRIVATE ${CONTRIB_DEFINITIONS})
target_link_libraries(lwipcontribportunix PUBLIC ${CONTRIB_LINK_LIBRARIES})

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_library(LIBUTIL util)
    find_library(LIBPTHREAD pthread)
    find_library(LIBRT rt)
    target_link_libraries(lwipcontribportunix PUBLIC ${LIBUTIL} ${LIBPTHREAD} ${LIBRT})
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # Darwin doesn't have pthreads or POSIX real-time extensions libs
    find_library(LIBUTIL util)
    target_link_libraries(lwipcontribportunix PUBLIC ${LIBUTIL})
endif()
