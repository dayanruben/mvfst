load("@fbcode_macros//build_defs:autodeps_rule.bzl", "autodeps_rule")
load("@fbcode_macros//build_defs:cpp_benchmark.bzl", "cpp_benchmark")
load("@fbcode_macros//build_defs:cpp_binary.bzl", "cpp_binary")
load("@fbcode_macros//build_defs:cpp_unittest.bzl", "cpp_unittest")
load("@fbsource//tools/build_defs:buckconfig.bzl", "read_bool")
load("@fbsource//tools/build_defs:cell_defs.bzl", "get_fbsource_cell")
load(
    "@fbsource//tools/build_defs:default_platform_defs.bzl",
    "ANDROID",
    "APPLE",
    "CXX",
    "FBCODE",
    "IOS",
    "MACOSX",
    "WINDOWS",
)
load("@fbsource//tools/build_defs:fb_xplat_cxx_binary.bzl", "fb_xplat_cxx_binary")
load("@fbsource//tools/build_defs:fb_xplat_cxx_library.bzl", "fb_xplat_cxx_library")
load("@fbsource//tools/build_defs:fb_xplat_cxx_test.bzl", "fb_xplat_cxx_test")
load("@fbsource//tools/build_defs/dirsync:fb_dirsync_cpp_library.bzl", "fb_dirsync_cpp_library")
load("@fbsource//tools/build_defs/xplat:deps_map_utils.bzl", "deps_map_utils")
load("@fbsource//xplat/pfh/Infra_Networking_Core:DEFS.bzl", "Infra_Networking_Core")

CXXFLAGS = [
    "-frtti",
    "-fexceptions",
    "-Wno-nullability-completeness",
    "-Wno-implicit-fallthrough",
]

FBANDROID_CXXFLAGS = [
    "-ffunction-sections",
    "-Wno-nullability-completeness",
    "-fstack-protector-strong",
] + ([
    "-flazy-init-all",
] if read_bool("ndk", "flazy_init_all", False) else [])

FBOBJC_CXXFLAGS = [
    "-Wno-global-constructors",
    "-fstack-protector-strong",
]

WINDOWS_MSVC_CXXFLAGS = [
    "/EHs",
    "/D_ENABLE_EXTENDED_ALIGNED_STORAGE",
]

WINDOWS_CLANG_CXX_FLAGS = [
    "-Wno-deprecated-declarations",
    "-Wno-microsoft-cast",
    "-Wno-missing-braces",
    "-Wno-unused-function",
    "-Wno-undef",
    "-DBOOST_HAS_THREADS",
    "-D_ENABLE_EXTENDED_ALIGNED_STORAGE",
]

DEFAULT_APPLE_SDKS = (IOS, MACOSX)
DEFAULT_PLATFORMS = (CXX, ANDROID, APPLE, FBCODE, WINDOWS)

def _compute_include_directories():
    base_path = native.package_name()
    if base_path == "xplat/quic":
        return [".."]
    quic_path = base_path[6:]
    return ["/".join(len(quic_path.split("/")) * [".."])]

def _compute_header_namespace():
    base_path = native.package_name()
    return base_path[6:]

def mvfst_cpp_library(
        name,
        autodeps_skip = False,
        compiler_flags = [],
        **kwargs):
    fb_dirsync_cpp_library(
        name = name,
        compiler_flags = select({
            "DEFAULT": compiler_flags + CXXFLAGS + select({
                "DEFAULT": [],
                "ovr_config//os:android": FBANDROID_CXXFLAGS,
                "ovr_config//os:iphoneos": FBOBJC_CXXFLAGS,
                "ovr_config//os:macos": FBOBJC_CXXFLAGS,
                "ovr_config//os:windows": WINDOWS_CLANG_CXX_FLAGS,
            }),
            "ovr_config//compiler:msvc": WINDOWS_MSVC_CXXFLAGS,
        }),
        feature = Infra_Networking_Core,
        **kwargs
    )

    if not autodeps_skip:
        autodeps_rule(
            name = name,
            type = "mvfst_cpp_library",
            attrs = kwargs,
        )

# TODO: Turn this into an internal implementation detail
def mvfst_cxx_library(
        name,
        srcs = (),
        headers = (),
        exported_headers = (),
        raw_headers = (),
        deps = (),
        exported_deps = (),
        force_static = False,
        apple_sdks = None,
        platforms = None,
        enable_static_variant = False,
        compiler_flags = [],
        labels = (),
        header_namespace = "",
        **kwargs):
    """Translate a simpler declartion into the more complete library target"""

    # Set default platform settings. `()` means empty, whereas None
    # means default
    if apple_sdks == None:
        apple_sdks = DEFAULT_APPLE_SDKS
    if platforms == None:
        platforms = DEFAULT_PLATFORMS

    # We use gflags on fbcode platforms, which don't mix well when mixing static
    # and dynamic linking.
    force_static = select({
        "DEFAULT": select({
            "DEFAULT": force_static,
            "ovr_config//runtime:fbcode": False,
        }),
        "ovr_config//build_mode:arvr_mode": force_static,
    })

    fb_xplat_cxx_library(
        name = name,
        srcs = srcs,
        header_namespace = header_namespace,
        headers = headers,
        exported_headers = exported_headers,
        raw_headers = raw_headers,
        public_include_directories = _compute_include_directories(),
        deps = deps,
        exported_deps = exported_deps,
        force_static = force_static,
        apple_sdks = apple_sdks,
        platforms = platforms,
        enable_static_variant = enable_static_variant,
        labels = list(labels),
        compiler_flags = select({
            "DEFAULT": compiler_flags + CXXFLAGS + select({
                "DEFAULT": [],
                "ovr_config//os:android": FBANDROID_CXXFLAGS,
                "ovr_config//os:iphoneos": FBOBJC_CXXFLAGS,
                "ovr_config//os:macos": FBOBJC_CXXFLAGS,
                "ovr_config//os:windows": WINDOWS_CLANG_CXX_FLAGS,
            }),
            "ovr_config//compiler:msvc": WINDOWS_MSVC_CXXFLAGS,
        }),
        windows_preferred_linkage = "static",
        visibility = kwargs.pop("visibility", ["PUBLIC"]),
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        feature = Infra_Networking_Core,
        **kwargs
    )

def mvfst_cpp_test(
        name,
        autodeps_skip = False,
        deps = (),
        external_deps = (),
        header_namespace = None,
        **kwargs):
    # Convert deps and external_deps
    if get_fbsource_cell() == "fbcode":
        cpp_unittest(
            name = name,
            autodeps_skip = True,
            deps = deps,
            external_deps = external_deps,
            header_namespace = header_namespace,
            **kwargs
        )

        if not autodeps_skip:
            autodeps_rule(
                name = name,
                type = "mvfst_cpp_test",
                attrs = kwargs,
            )
    else:
        deps = deps_map_utils.convert_to_fbsource_fp_deps(deps) + deps_map_utils.convert_to_fbsource_tp_deps(external_deps)
        mvfst_cxx_test(
            name,
            deps = deps,
            header_namespace = header_namespace or _compute_header_namespace(),
            visibility = ["PUBLIC"],
            **kwargs
        )

def mvfst_cxx_test(
        name,
        srcs,
        headers = [],
        deps = [],
        header_namespace = "",
        **kwargs):
    fb_xplat_cxx_test(
        name = name,
        srcs = srcs,
        headers = headers,
        header_namespace = header_namespace,
        deps = deps,
        # Combination of `platforms = FBCODE` and `mangled_keys = ["deps"]`
        # forces the unsuffixed target into fbcode platform
        platforms = (FBCODE,),
        mangled_keys = ["deps"],
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        **kwargs
    )

def mvfst_cpp_binary(
        name,
        autodeps_skip = False,
        deps = (),
        external_deps = (),
        header_namespace = None,
        **kwargs):
    # Convert deps and external_deps
    if get_fbsource_cell() == "fbcode":
        cpp_binary(
            name = name,
            autodeps_skip = True,
            deps = deps,
            external_deps = external_deps,
            header_namespace = header_namespace,
            **kwargs
        )

        if not autodeps_skip:
            autodeps_rule(
                name = name,
                type = "mvfst_cpp_binary",
                attrs = kwargs,
            )
    else:
        deps = deps_map_utils.convert_to_fbsource_fp_deps(deps) + deps_map_utils.convert_to_fbsource_tp_deps(external_deps)
        mvfst_cxx_binary(
            name,
            deps = deps,
            header_namespace = header_namespace or _compute_header_namespace(),
            visibility = ["PUBLIC"],
            **kwargs
        )

def mvfst_cxx_binary(
        name,
        srcs,
        headers = [],
        compatible_with = [],
        compiler_flags = [],
        deps = [],
        header_namespace = "",
        **kwargs):
    fb_xplat_cxx_binary(
        name = name,
        srcs = srcs,
        headers = headers,
        header_namespace = header_namespace,
        compatible_with = compatible_with,
        compiler_flags = compiler_flags + CXXFLAGS,
        deps = deps,
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        platforms = (CXX,),
        **kwargs
    )

def mvfst_cpp_benchmark(
        name,
        autodeps_skip = False,
        deps = (),
        external_deps = (),
        header_namespace = None,
        **kwargs):
    # Convert deps and external_deps
    if get_fbsource_cell() == "fbcode":
        cpp_benchmark(
            name = name,
            autodeps_skip = True,
            deps = deps,
            external_deps = external_deps,
            header_namespace = header_namespace,
            **kwargs
        )

        if not autodeps_skip:
            autodeps_rule(
                name = name,
                type = "mvfst_cpp_benchmark",
                attrs = kwargs,
            )
    else:
        # Don't generate xplat benchmark targets
        pass

def mu_cxx_library(
        name,
        srcs = (),
        headers = (),
        exported_headers = (),
        raw_headers = (),
        deps = (),
        exported_deps = (),
        force_static = False,
        apple_sdks = None,
        platforms = None,
        enable_static_variant = False,
        labels = (),
        fbandroid_labels = (),
        fbobjc_labels = (),
        header_namespace = "",
        **kwargs):
    """Translate a simpler declartion into the more complete library target"""

    # Set default platform settings. `()` means empty, whereas None
    # means default
    if apple_sdks == None:
        apple_sdks = DEFAULT_APPLE_SDKS
    if platforms == None:
        platforms = DEFAULT_PLATFORMS

    # We use gflags on fbcode platforms, which don't mix well when mixing static
    # and dynamic linking.
    force_static = select({
        "DEFAULT": select({
            "DEFAULT": force_static,
            "ovr_config//runtime:fbcode": False,
        }),
        "ovr_config//build_mode:arvr_mode": force_static,
    })

    fb_xplat_cxx_library(
        name = name,
        srcs = srcs,
        header_namespace = header_namespace,
        headers = headers,
        exported_headers = exported_headers,
        raw_headers = raw_headers,
        public_include_directories = _compute_include_directories(),
        deps = deps,
        exported_deps = exported_deps,
        force_static = force_static,
        apple_sdks = apple_sdks,
        platforms = platforms,
        enable_static_variant = enable_static_variant,
        labels = list(labels),
        fbandroid_labels = list(fbandroid_labels),
        fbobjc_labels = list(fbobjc_labels),
        compiler_flags = select({
            "DEFAULT": kwargs.pop("compiler_flags", []) + CXXFLAGS,
            "config//compiler:msvc": WINDOWS_MSVC_CXXFLAGS,
        }),
        windows_compiler_flags = kwargs.pop("windows_compiler_flags", []) + CXXFLAGS + WINDOWS_CLANG_CXX_FLAGS,
        fbobjc_compiler_flags = kwargs.pop("fbobjc_compiler_flags", []) +
                                FBOBJC_CXXFLAGS,
        fbcode_compiler_flags_override = kwargs.pop("fbcode_compiler_flags", []),
        fbandroid_compiler_flags = kwargs.pop("fbandroid_compiler_flags", []) +
                                   FBANDROID_CXXFLAGS,
        windows_preferred_linkage = "static",
        visibility = kwargs.pop("visibility", ["PUBLIC"]),
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        feature = Infra_Networking_Core,
        **kwargs
    )

def mu_cxx_test(
        name,
        srcs,
        raw_headers = [],
        deps = []):
    fb_xplat_cxx_test(
        name = name,
        srcs = srcs,
        raw_headers = raw_headers,
        include_directories = [
            "..",
        ],
        deps = deps,
        platforms = (CXX,),
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
    )

def mu_cxx_binary(
        name,
        srcs,
        raw_headers = [],
        deps = [],
        **kwargs):
    fb_xplat_cxx_binary(
        name = name,
        srcs = srcs,
        raw_headers = raw_headers,
        compiler_flags = kwargs.pop("compiler_flags", []) + CXXFLAGS,
        include_directories = [
            "..",
        ],
        deps = deps,
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        platforms = (CXX,),
    )
