cmake_minimum_required(VERSION 3.0)

# Set the project name and version
project(SimpleHTTPServer VERSION 1.0)

# Specify the C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# Add an executable with the above sources
add_executable(http_server server.c)
