
cmake_minimum_required(VERSION 3.23)
project(teams_analysis)

set(CMAKE_CXX_STANDARD 17)

include(cmake/catch.cmake)
include(cmake/cxxopts.cmake)
include(cmake/pcap.cmake)

set(TEAMS_ANALYSIS_LIB_PCAP_SRC
    lib/pcap_file_reader.h lib/pcap_file_reader.cc
    lib/pcap_file_writer.h lib/pcap_file_writer.cc)

set(TEAMS_ANALYSIS_LIB_SRC
    lib/file_stream.h
    lib/fps_calculator.h lib/fps_calculator.cc
    lib/jitter_calculator.h lib/jitter_calculator.cc
    lib/mac_counter.h lib/mac_counter.cc
    lib/net.h lib/net.cc
    lib/ring_buffer.h
    lib/rtcp.h
    lib/rtp.h
    lib/rtp_stream_analyzer.h
    lib/simple_binary_reader.h
    lib/simple_binary_writer.h
    lib/teams.h lib/teams.cc
    lib/teams_analyzer.h lib/teams_analyzer.cc
    lib/teams_flow_tracker.h lib/teams_flow_tracker.cc
    lib/teams_nets.h
    lib/teams_offline_analyzer.h lib/teams_offline_analyzer.cc)


list(TRANSFORM TEAMS_ANALYSIS_LIB_PCAP_SRC PREPEND src/)
list(TRANSFORM TEAMS_ANALYSIS_LIB_SRC PREPEND src/)


#### teams_flows:

add_executable(teams_flows
    ${TEAMS_ANALYSIS_LIB_SRC}
    ${TEAMS_ANALYSIS_LIB_PCAP_SRC}
    src/cmd/teams_flows.h
    src/cmd/teams_flows_main.cc)
target_include_directories(teams_flows PUBLIC ext/include)
target_link_libraries(teams_flows ${PCAP_LIBRARIES})
set_target_properties(teams_flows PROPERTIES LINKER_LANGUAGE CXX)


#### teams_rtp:

add_executable(teams_rtp
    ${TEAMS_ANALYSIS_LIB_SRC} src/cmd/teams_rtp.h
    src/cmd/teams_rtp_main.cc)
target_include_directories(teams_rtp PUBLIC ext/include)
set_target_properties(teams_rtp PROPERTIES LINKER_LANGUAGE CXX)


#### teams_rtp:

add_executable(teams_meetings
        ${TEAMS_ANALYSIS_LIB_SRC} src/cmd/teams_meetings.h
        src/cmd/teams_meetings_main.cc)
target_include_directories(teams_meetings PUBLIC ext/include)
set_target_properties(teams_meetings PROPERTIES LINKER_LANGUAGE CXX)


#### unit testing:

enable_testing()
add_subdirectory(test)
