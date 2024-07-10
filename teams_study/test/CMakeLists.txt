
list(TRANSFORM TEAMS_ANALYSIS_LIB_SRC PREPEND ../)
list(TRANSFORM TEAMS_ANALYSIS_LIB_PCAP_SRC PREPEND ../)

set(TEAMS_ANALYSIS_TEST_SRC
    mac_counter_test.cc
    pcap_file_reader_test.cc
    rtp_test.cc
    teams_flow_tracker_test.cc
    teams_nets_test.cc
    teams_pkt_test.cc
    teams_test.cc)

add_executable(unit
        unit_main.cc
        ${TEAMS_ANALYSIS_TEST_SRC}
        ${TEAMS_ANALYSIS_LIB_PCAP_SRC}
        ${TEAMS_ANALYSIS_LIB_SRC})

target_include_directories(unit PUBLIC ${PROJECT_SOURCE_DIR}/src)
target_include_directories(unit PUBLIC ${PROJECT_SOURCE_DIR}/test/include)
target_include_directories(unit PUBLIC ${PCAP_INCLUDE_DIRS})
target_link_libraries(unit ${PCAP_LIBRARIES})

add_test(NAME unit COMMAND unit WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR})
