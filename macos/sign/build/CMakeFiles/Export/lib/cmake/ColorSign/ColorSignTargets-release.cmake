#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "ColorSign::colorsign_macos" for configuration "Release"
set_property(TARGET ColorSign::colorsign_macos APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(ColorSign::colorsign_macos PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libcolorsign_macos.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS ColorSign::colorsign_macos )
list(APPEND _IMPORT_CHECK_FILES_FOR_ColorSign::colorsign_macos "${_IMPORT_PREFIX}/lib/libcolorsign_macos.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
