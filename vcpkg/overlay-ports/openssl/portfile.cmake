vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO openssl/openssl
    REF "openssl-${VERSION}"
    SHA512 40f0b346a9a5cf4cb37f1ecebdc74750c39a95783710061bfac58964883b0831543ecee0aee9f747ea093781b13c58a543b0b935d222519e3cb19648d77a0276
    PATCHES
        no-static-pdb.patch
        no-avx512-aes.patch
)

vcpkg_list(SET CONFIGURE_OPTIONS
    no-shared
    no-module
    no-apps
    no-tests
    no-docs
    no-makedepend
    no-autoload-config
    no-engine
    no-legacy
    no-err
    no-sock
    no-http
    no-ui-console
    no-multiblock
    no-aria
    no-bf
    no-blake2
    no-camellia
    no-cast
    no-des
    no-dh
    no-dsa
    no-ec2m
    no-idea
    no-md4
    no-mdc2
    no-ocb
    no-rc2
    no-rc4
    no-rc5
    no-rmd160
    no-seed
    no-siphash
    no-siv
    no-sm2
    no-sm3
    no-sm4
    no-srp
    no-whirlpool
    no-argon2
    no-ml-kem
    no-ml-dsa
    no-slh-dsa
    no-lms
    no-cms
    no-cmp
    no-ct
    no-ocsp
    no-ts
    no-comp
    no-gost
)

# Need cmd to pass quoted CC from nmake to mkbuildinf.pl, GH-37134
find_program(CMD_EXECUTABLE cmd HINTS ENV PATH NO_DEFAULT_PATH REQUIRED)
cmake_path(NATIVE_PATH CMD_EXECUTABLE cmd)
set(ENV{COMSPEC} "${cmd}")

vcpkg_find_acquire_program(PERL)
cmake_path(GET PERL PARENT_PATH perl_path)
vcpkg_add_to_path("${perl_path}")

vcpkg_find_acquire_program(NASM)
cmake_path(NATIVE_PATH NASM NORMALIZE as)
cmake_path(GET NASM PARENT_PATH nasm_path)
vcpkg_add_to_path("${nasm_path}")

vcpkg_cmake_get_vars(cmake_vars_file)
include("${cmake_vars_file}")
cmake_path(NATIVE_PATH VCPKG_DETECTED_CMAKE_C_COMPILER NORMALIZE cc)
cmake_path(NATIVE_PATH VCPKG_DETECTED_CMAKE_AR NORMALIZE ar)
cmake_path(NATIVE_PATH VCPKG_DETECTED_CMAKE_LINKER NORMALIZE ld)
cmake_path(NATIVE_PATH CURRENT_PACKAGES_DIR NORMALIZE packages_dir)

vcpkg_build_nmake(
    SOURCE_PATH "${SOURCE_PATH}"
    PREFER_JOM
    CL_LANGUAGE NONE
    PRERUN_SHELL_RELEASE "${PERL}" Configure
        ${CONFIGURE_OPTIONS}
        VC-WIN64A
        "AS=${as}"
        "CC=${cc}"
        "CFLAGS=${VCPKG_COMBINED_C_FLAGS_RELEASE}"
        "AR=${ar}"
        "ARFLAGS=${VCPKG_COMBINED_STATIC_LINKER_FLAGS_RELEASE}"
        "LD=${ld}"
    PRERUN_SHELL_DEBUG "${PERL}" Configure
        ${CONFIGURE_OPTIONS}
        VC-WIN64A
        --debug
        "AS=${as}"
        "CC=${cc}"
        "CFLAGS=${VCPKG_COMBINED_C_FLAGS_DEBUG}"
        "AR=${ar}"
        "ARFLAGS=${VCPKG_COMBINED_STATIC_LINKER_FLAGS_DEBUG}"
        "LD=${ld}"
    PROJECT_NAME "makefile"
    TARGET install_dev
    LOGFILE_ROOT install
    OPTIONS_RELEASE
        "DESTDIR=${packages_dir}"
    OPTIONS_DEBUG
        "DESTDIR=${packages_dir}\\debug"
)

file(GLOB release_prefix "${CURRENT_PACKAGES_DIR}/Program*")
file(GLOB debug_prefix "${CURRENT_PACKAGES_DIR}/debug/Program*")
file(RENAME "${release_prefix}/OpenSSL/include" "${CURRENT_PACKAGES_DIR}/include")
file(RENAME "${release_prefix}/OpenSSL/lib" "${CURRENT_PACKAGES_DIR}/lib")
file(RENAME "${debug_prefix}/OpenSSL/lib" "${CURRENT_PACKAGES_DIR}/debug/lib")
file(REMOVE_RECURSE
    "${release_prefix}"
    "${debug_prefix}"
    "${CURRENT_PACKAGES_DIR}/lib/cmake"
    "${CURRENT_PACKAGES_DIR}/lib/pkgconfig"
    "${CURRENT_PACKAGES_DIR}/debug/lib/cmake"
    "${CURRENT_PACKAGES_DIR}/debug/lib/pkgconfig"
)

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE.txt")
