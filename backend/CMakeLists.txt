cmake_minimum_required(VERSION 3.9)

project(
  mtg-search-engine
  VERSION 1.5
  LANGUAGES C CXX)

# Clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)
set(REPO_URL "https://github.com/djpiper28/mtg-search-engine")

message(STATUS "Building ${CMAKE_PROJECT_NAME}")
message(STATUS "Git repo: ${REPO_URL}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Version: ${CMAKE_PROJECT_VERSION}")
message(STATUS "Build OS: ${CMAKE_SYSTEM_NAME}")

# Get the branch name
execute_process(
  COMMAND git rev-parse --abbrev-ref HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_BRANCH
  OUTPUT_STRIP_TRAILING_WHITESPACE)

# Get the latest abbreviated commit hash of the working branch
execute_process(
  COMMAND git log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE)
message(STATUS "Commit info: ${GIT_COMMIT_HASH}@${GIT_BRANCH}")

# Version info
add_definitions("-DMSE_GIT_COMMIT_HASH=\"${GIT_COMMIT_HASH}\"")
add_definitions("-DMSE_GIT_BRANCH=\"${GIT_BRANCH}\"")
add_definitions(
  "-DMSE_VERSION=\"${CMAKE_PROJECT_VERSION} (${GIT_COMMIT_HASH}@${GIT_BRANCH})\""
)
add_definitions("-DMSE_OS=\"${CMAKE_SYSTEM_NAME}\"")
add_definitions("-DMSE_REPO_URL=\"${REPO_URL}\"")
add_definitions("-DMSE_PROJECT_VERSION=\"${CMAKE_PROJECT_VERSION}\"")
add_definitions("-DMSE_PROJECT_NAME=\"${CMAKE_PROJECT_NAME}\"")

# __FILENAME__
string(LENGTH "${CMAKE_SOURCE_DIR}/" SOURCE_PATH_SIZE)
add_definitions("-DSOURCE_PATH_SIZE=${SOURCE_PATH_SIZE}")
add_definitions("-D__FILENAME__=(&__FILE__[SOURCE_PATH_SIZE])")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)

if(NOT WIN32)
  set(OPTIMISATION "-Ofast")
  if(USE_GCOV)
    set(OPTIMISATION)
  endif()

  set(CMAKE_C_FLAGS
      "-std=gnu11 -Wpedantic -Werror -Wno-unused-parameter -Wno-overlength-strings ${OPTIMISATION} -march=native  -Wno-deprecated-declarations -Wno-strict-prototypes -Wno-newline-eof"
  )
endif()

# Generated sources
set(MTG_JSON_FILE ${CMAKE_CURRENT_BINARY_DIR}/AllPrintings.json)
add_custom_command(
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/codegen/download_mtg_json.py
  OUTPUT ${MTG_JSON_FILE}
  COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/codegen/download_mtg_json.py
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set(LANG_SOURCE_FILES ${CMAKE_CURRENT_BINARY_DIR}/mse_langs.h
                      ${CMAKE_CURRENT_BINARY_DIR}/mse_langs.c)
add_custom_command(
  DEPENDS ${MTG_JSON_FILE}
          ${CMAKE_CURRENT_SOURCE_DIR}/codegen/generate_languages_files.py
  OUTPUT ${LANG_SOURCE_FILES}
  COMMAND python3
          ${CMAKE_CURRENT_SOURCE_DIR}/codegen/generate_languages_files.py
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set(FILTER_SOURCE_FILES ${CMAKE_CURRENT_BINARY_DIR}/mse_char_map.h
                        ${CMAKE_CURRENT_BINARY_DIR}/mse_char_map.c)
add_custom_command(
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/codegen/generate_char_map.py
  OUTPUT ${FILTER_SOURCE_FILES}
  COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/codegen/generate_char_map.py
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set(FORMAT_SOURCE_FILES ${CMAKE_CURRENT_BINARY_DIR}/mse_formats.h
                        ${CMAKE_CURRENT_BINARY_DIR}/mse_formats.c)
add_custom_command(
  DEPENDS ${MTG_JSON_FILE}
          ${CMAKE_CURRENT_SOURCE_DIR}/codegen/generate_formats.py
  OUTPUT ${FORMAT_SOURCE_FILES}
  COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/codegen/generate_formats.py
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

# Pack CC executable
add_executable(packcc vendor/packcc/src/packcc.c)

# Enabled by default to make coredumps usable
option(DEBUG ON)
if(DEBUG)
  if(NOT WIN32)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
  endif()
  set(PEG_DEBUG "--debug")
else()
  set(PEG_DEBUG "")
endif()

set(PEG_PREFIX mse_query_parser)
set(PARSER_SRC ${CMAKE_CURRENT_BINARY_DIR}/${PEG_PREFIX}.c
               ${CMAKE_CURRENT_BINARY_DIR}/${PEG_PREFIX}.h)
add_custom_command(
  DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/packcc
          ${CMAKE_CURRENT_SOURCE_DIR}/mse/query_parser.peg
  COMMAND packcc -o ${PEG_PREFIX} --lines ${PEG_DEBUG}
          ${CMAKE_CURRENT_SOURCE_DIR}/mse/query_parser.peg
  OUTPUT ${PARSER_SRC}
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

# Packages
find_package(CURL)

# Jansson find_package is broken On non-unix systems. find_package(jansson)

# you need to provide your own pthreads implementation Have a look at win32
# pthreads for example

# Assumption is that absl works
set(ABSL_BUILD_TESTING OFF)
set(ABSL_PROPAGATE_CXX_STD ON)
set(ABSL_ENABLE_INSTALL ON)

add_subdirectory(./vendor/abseil)
# find_package(absl)
set(ABSL_LIBS
    absl::base
    absl::core_headers
    absl::fixed_array
    absl::flags
    absl::flat_hash_map
    absl::flat_hash_set
    absl::inlined_vector
    absl::optional
    absl::span
    absl::str_format
    absl::strings)

add_subdirectory(./vendor/re2)

add_subdirectory(./vendor/utf8proc/)

option(USE_JEMALLOC OFF)
set(LIBS jansson CURL::libcurl pthread ${ABSL_LIBS} re2 utf8proc)
if(USE_JEMALLOC)
  set(LIBS ${LIBS} jemalloc)
endif()

# Define the sources
set(SRC
    ./vendor/testing_h/ansi_colour.h
    ./vendor/testing_h/testing.h
    ./vendor/testing_h/testing.c
    ./vendor/testing_h/logger.h
    ./vendor/testing_h/logger.c
    ./mse/card.h
    ./mse/card.c
    ./mse/card_str_match.h
    ./mse/card_str_match.c
    ./mse/card_txt_fields_trie.h
    ./mse/card_txt_fields_trie.c
    ./mse/set.h
    ./mse/set.c
    ./mse/uuid.h
    ./mse/uuid.c
    ./mse/mtg_json.h
    ./mse/mtg_json.c
    ./mse/mtg_json_indexes.h
    ./mse/mtg_json_indexes.c
    ./mse/thread_pool.h
    ./mse/thread_pool.c
    ./mse/io_utils.h
    ./mse/io_utils.c
    ./mse/avl_tree.h
    ./mse/avl_tree.c
    ./mse/search.h
    ./mse/search.c
    ./mse/generator_set.h
    ./mse/generator_set.c
    ./mse/generators.h
    ./mse/generators.c
    ./mse/generator_float_fields.h
    ./mse/generator_float_fields.c
    ./mse/generator_oracle.h
    ./mse/generator_oracle.c
    ./mse/generator_colour.h
    ./mse/generator_colour.c
    ./mse/generator_name.h
    ./mse/generator_name.c
    ./mse/generator_type.h
    ./mse/generator_type.c
    ./mse/interpretor.h
    ./mse/interpretor.c
    ./mse/consumer.h
    ./mse/consumer.c
    ./mse/save.h
    ./mse/save.c
    ./mse/mse.h
    ./mse/mse.c
    ./mse/re2_wrapper.h
    ./mse/re2_wrapper.cpp
    ./mse/query_parser.h
    ./mse/query_parser_internals.c
    ./mse/levenshtein_difference.h
    ./mse/levenshtein_difference.c
    ./mse/utf8_normalisation.h
    ./mse/utf8_normalisation.c
    ./mse/async_query.h
    ./mse/async_query.c
    ./vendor/strptime/strptime.h
    ./vendor/strptime/strptime.c
    ${PARSER_SRC}
    ${FILTER_SOURCE_FILES}
    ${LANG_SOURCE_FILES}
    ${FORMAT_SOURCE_FILES})
set(TESTS
    ./tests/main.c
    ./tests/test_thread_pool.h
    ./tests/test_thread_pool.c
    ./tests/test_mtg_json.h
    ./tests/test_mtg_json.c
    ./tests/test_uuid.h
    ./tests/test_uuid.c
    ./tests/test_io_utils.h
    ./tests/test_io_utils.c
    ./tests/test_set.h
    ./tests/test_set.c
    ./tests/test_card.h
    ./tests/test_card.c
    ./tests/test_card_str_match.h
    ./tests/test_card_str_match.c
    ./tests/test_card_txt_field_trie.h
    ./tests/test_card_txt_field_trie.c
    ./tests/test_avl_tree.h
    ./tests/test_avl_tree.c
    ./tests/test_search.h
    ./tests/test_search.c
    ./tests/test_generators.h
    ./tests/test_generators.c
    ./tests/test_generator_validation.c
    ./tests/test_generator_double_fields.c
    ./tests/test_generator_set.c
    ./tests/test_generator_txt.c
    ./tests/test_generator_colours.c
    ./tests/test_generator_type.c
    ./tests/test_consumer.c
    ./tests/test_interpretor.h
    ./tests/test_interpretor.c
    ./tests/test_parser.h
    ./tests/test_parser.c
    ./tests/test_mse_langs.h
    ./tests/test_mse_langs.c
    ./tests/test_save.h
    ./tests/test_save.c
    ./tests/test_re2.h
    ./tests/test_re2.c
    ./tests/test_formats.h
    ./tests/test_formats.c
    ./tests/test_levenshtein_difference.h
    ./tests/test_levenshtein_difference.c
    ./tests/test_utf8_normalisation.h
    ./tests/test_utf8_normalisation.c
    ./tests/test_async_query.h
    ./tests/test_async_query.c
    ./tests/system_test.h
    ./tests/system_test.c)
set(WEB_API ./web-api/main.c ./web-api/server.c ./web-api/server.h
            ./vendor/mongoose/mongoose.c ./vendor/mongoose/mongoose.h)

# Setup gcovr
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/scripts/cmake)

# Add library and cli execs
add_library(mtg-search-engine OBJECT ${SRC})
target_link_libraries(mtg-search-engine PRIVATE ${LIBS})
target_include_directories(
  mtg-search-engine
  PUBLIC ${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}
         ${CMAKE_CURRENT_SOURCE_DIR}/vendor)

add_executable(mtg-search-engine-cli mse/main.c)
target_link_libraries(mtg-search-engine-cli ${LIBS} mtg-search-engine)

add_executable(mtg-search-engine-web-api ${WEB_API})
target_link_libraries(
  mtg-search-engine-web-api
  ${LIBS}
  crypto
  mbedtls
  mbedcrypto
  mbedx509
  mtg-search-engine)

option(ADDRESS_SANITISER OFF)
if(ADDRESS_SANITISER)
  link_libraries(-fsanitize=address)
endif()

# Setup docs
option(MSE_DOXYGEN OFF)
if(MSE_DOXYGEN)
  find_package(doxygen REQUIRED dot OPTIONAL_COMPONENTS mscgen dia)
  doxygen_add_docs(mse-docs ${SRC} ${TESTS}
                   "Generate documentation pages for ${REPO_URL}")
endif()

option(USE_GCOV ON)
if(USE_GCOV)
  include(CodeCoverage)
  set(GCOVR_EXCLUDE "build/*" "tests/*" "mse/main.c" "vendor/*" "web-api/*")

  append_coverage_compiler_flags()
  setup_target_for_coverage_gcovr_xml(
    NAME mse-coverage EXECUTABLE mtg-search-engine-tests EXCLUDE
    ${GCOVR_EXCLUDE})
endif()

# Setup unit tests
if(UNIX)
  add_executable(mtg-search-engine-tests ${TESTS})
  target_link_libraries(mtg-search-engine-tests PUBLIC ${LIBS}
                                                       mtg-search-engine)

  # Copy test data
  set(TEST_CARD_JSON ${CMAKE_CURRENT_BINARY_DIR}/test_card.json)
  set(TEST_CARD_JSON_NO_ORIGINAL_TEXT
      ${CMAKE_CURRENT_BINARY_DIR}/test_card_no_originalText.json)
  set(TEST_VALID_QUERIES ${CMAKE_CURRENT_BINARY_DIR}/valid_queries.txt)
  set(TEST_INVALID_QUERIES ${CMAKE_CURRENT_BINARY_DIR}/invalid_queries.txt)

  set(MEM_TESTS_SH ${CMAKE_CURRENT_BINARY_DIR}/mem_tests.sh)
  set(MEM_TESTS_PY ${CMAKE_CURRENT_BINARY_DIR}/mem_tests.py)
  set(TESTING_SCRIPTS ${MEM_TESTS_PY} ${MEM_TESTS_SH})

  set(TEST_DATA_FILES
      ${TEST_CARD_JSON} ${TEST_CARD_JSON_NO_ORIGINAL_TEXT} ${TESTING_SCRIPTS}
      ${TEST_VALID_QUERIES} ${TEST_INVALID_QUERIES} ${ALL_PRINTINGS})
  add_custom_command(
    OUTPUT ${TEST_DATA_FILES}
    COMMAND ${CMAKE_COMMAND} -E copy
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_card.json ${TEST_CARD_JSON}
    COMMAND
      ${CMAKE_COMMAND} -E copy
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/test_card_no_originalText.json
      ${TEST_CARD_JSON_NO_ORIGINAL_TEXT}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/mem_tests.sh
            ${MEM_TESTS_SH}
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/mem_tests.py
            ${MEM_TESTS_PY}
    COMMAND
      ${CMAKE_COMMAND} -E copy
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/valid_queries.txt ${TEST_VALID_QUERIES}
    COMMAND
      ${CMAKE_COMMAND} -E copy
      ${CMAKE_CURRENT_SOURCE_DIR}/tests/invalid_queries.txt
      ${TEST_INVALID_QUERIES})
  add_custom_target(TEST_DATA DEPENDS ${TEST_DATA_FILES})
  add_dependencies(mtg-search-engine-tests TEST_DATA)

  # Testing
  enable_testing()
  add_test(NAME main-tests COMMAND mtg-search-engine-tests)
  add_test(NAME memory-tests COMMAND bash ${MEM_TESTS_SH})
endif()
