include(BundleUtilities)

message("Fixing up ${EXECUTABLE} using binaries from ${SEARCH_DIRS}")

fixup_bundle("${EXECUTABLE}" "" "${SEARCH_DIRS}")