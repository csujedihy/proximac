SET(CMAKE_C_FLAGS "-std=gnu99 -g -O2")
SET(LOCAL_SRC_LIST local.c js0n.c utils.c jconf.c)
ADD_EXECUTABLE(proximac ${LOCAL_SRC_LIST})
TARGET_LINK_LIBRARIES(proximac uv)