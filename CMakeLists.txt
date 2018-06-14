#cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr
cmake_minimum_required(VERSION 2.8.11)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/../cmake")
set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -g")

#add_subdirectory(3rdparty/backward-cpp)

function(make_tests)
	foreach(arg ${ARGN})
		add_executable(test_${arg} src/${arg}.c)
		target_link_libraries(test_${arg} s2p -lcunit)
		add_test(NAME ${arg} COMMAND test_${arg})
		set_target_properties(test_${arg} PROPERTIES COMPILE_FLAGS "-DTESTING")
	endforeach()
endfunction()

project(s2p)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
include_directories("${CMAKE_SOURCE_DIR}")

set(s2p_SRC
	src/buffer.c
)

set(s2p_HDR
	s2p.h
	include/buffer.h
)

if(WIN32)
	#	include_directories(/home/humanist/mxe/usr/i686-w64-mingw32.static/qt/include/QtGui /home/humanist/mxe/usr/i686-w64-mingw32.static/qt/include/QtCore -isystem /home/humanist/mxe/usr/i686-w64-mingw32.static/qt/mkspecs/default -isystem /home/humanist/mxe/usr/i686-w64-mingw32.static/qt/include)
	#add_executable(s2p main.cpp textlex.cpp annotlex.cpp treedata.cpp mainwindow.cpp dispatch.cpp dialogs.cpp log.cpp widgets.cpp ${annotate_MOC_SRCS})
	#add_backward(annotate)
	#target_link_libraries(annotate -L/home/humanist/mxe/usr/i686-w64-mingw32.static/qt/lib/ -lQtGui -lQtCore -lz -ltiff -lpng -ljpeg -lmng -llcms2 -llzma -limm32 -lws2_32 -lwsock32 -lwinmm -lz)
	#target_link_libraries(annotate Qt4::QtGui -ltiff -lpng -ljpeg -lmng -llcms2 -llzma -lz -limm32 -lws2_32 -lwsock32 -lwinmm -lz)
endif(WIN32)
if(UNIX)
	add_library(s2p STATIC ${s2p_SRC})

	#	add_definitions(-DTESTING)
	enable_testing()
	make_tests(buffer)
endif(UNIX)
target_include_directories(s2p PRIVATE ${CMAKE_BINARY_DIR})

set_target_properties(s2p PROPERTIES PUBLIC_HEADER "${s2p_HDR}")
#install(TARGETS s2p
#	PUBLIC_HEADER DESTINATION include/s2p
#	ARCHIVE DESTINATION lib
#	LIBRARY DESTINATION lib)

