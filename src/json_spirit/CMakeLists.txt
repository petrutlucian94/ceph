add_library(json_spirit STATIC
  json_spirit_reader.cpp
  json_spirit_writer.cpp)
if(NOT WIN32)
  target_link_libraries(json_spirit common_utf8)
else()
  target_link_libraries(json_spirit common_utf8 Boost::thread)
endif()
