cmake_minimum_required(VERSION 3.20.0)

# This sample lives inside the SDK repo, so register the repo root as a Zephyr
# module (its zephyr/module.yml wires in the agent's Kconfig + CMakeLists). A
# customer who pulls the SDK in via their west manifest does not need this line.
list(APPEND EXTRA_ZEPHYR_MODULES ${CMAKE_CURRENT_SOURCE_DIR}/../..)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(meshanics_sensor_node)

target_sources(app PRIVATE src/main.c)
