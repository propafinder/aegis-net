# aws-lc-sys 0.44.0 names its archive with a GNU "lib" prefix when Clang
# uses the GNU command-line driver for an MSVC target. Rust's MSVC linker
# resolves the unprefixed aws_lc_0_44_0_{crypto,ssl}.lib names. Apply the
# Windows target names after the upstream project sets its PREFIX property;
# do not alter the symbols or compile options in the upstream library.
function(aegis_windows_arm64_archive_prefix)
  if(BORINGSSL_PREFIX AND TARGET crypto AND TARGET ssl)
    set_target_properties(crypto ssl PROPERTIES PREFIX "${BORINGSSL_PREFIX}")
  endif()
endfunction()
cmake_language(DEFER CALL aegis_windows_arm64_archive_prefix)
