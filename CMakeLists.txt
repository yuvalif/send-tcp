project(sendPkts)

set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

add_executable(sendIP ./send-ip.c)
target_link_libraries(sendIP pcap)
install(TARGETS sendIP DESTINATION bin)

add_executable(sendTCP ./send-tcp.c)
target_link_libraries(sendTCP pcap)
install(TARGETS sendTCP DESTINATION bin)

add_executable(sendABC ./send-abc.c)
target_link_libraries(sendABC pcap)
install(TARGETS sendABC DESTINATION bin)
