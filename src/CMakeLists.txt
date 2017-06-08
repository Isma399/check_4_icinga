

add_executable(check_linux_disk check_linux_disk.c)
add_executable(check_linux_inode check_linux_inode.c)
add_executable(check_linux_load check_linux_load.c)
add_executable(check_linux_ram check_linux_ram.c)

target_link_libraries(check_linux_disk ${NETSNMP_LIBRARIES})
target_link_libraries(check_linux_inode ${NETSNMP_LIBRARIES})
target_link_libraries(check_linux_load ${NETSNMP_LIBRARIES})
target_link_libraries(check_linux_ram ${NETSNMP_LIBRARIES})


install(TARGETS check_linux_disk check_linux_inode check_linux_load check_linux_ram
  ARCHIVE DESTINATION ${ARCHIVE_DIR}
  LIBRARY DESTINATION ${LIBRARY_DIR}
  RUNTIME DESTINATION ${RUNTIME_DIR}
)
