add_compile_options (-Wall)
add_compile_options (-g)

find_package (Threads REQUIRED)
if (THREAD_HAVE_PTHREAD_ARG)
  target_compile_options (PUBLIC fake_bitfiend "-pthread")
endif ()

aux_source_directory (. src)
add_executable (fake_bitfiend ${src})

if (CMAKE_THREAD_LIBS_INIT)
  target_link_libraries(fake_bitfiend "${CMAKE_THREAD_LIBS_INIT}" "rt")
endif ()
