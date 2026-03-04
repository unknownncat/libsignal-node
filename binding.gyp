{
  "targets": [
    {
      "target_name": "libsignal_native",
      "sources": [
        "native/libsignal_helpers.cpp",
        "native/libsignal_queue_session.cpp",
        "native/libsignal_crypto.cpp",
        "native/libsignal_async.cpp",
        "native/libsignal_native.cpp",
        "native/proto/WhisperTextProtocol.pb.cc"
      ],
      "defines": [ "NODE_ADDON_API_CPP_EXCEPTIONS" ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "<!(node -p \"require('path').join(process.env.USERPROFILE, 'vcpkg', 'installed', 'x64-windows', 'include')\")"
      ],
      "dependencies": [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      "cflags_cc!": [ "-fno-exceptions" ],
      "conditions": [
        [ "OS=='win'", {
          "defines": [ "PROTOBUF_USE_DLLS" ],
          "libraries": [
            "<!(node -p \"require('path').join(process.env.USERPROFILE, 'vcpkg', 'installed', 'x64-windows', 'lib', 'libprotobuf.lib')\")",
            "<!(node -p \"require('path').join(process.env.USERPROFILE, 'vcpkg', 'installed', 'x64-windows', 'lib', 'abseil_dll.lib')\")",
            "<!(node -p \"require('path').join(process.env.USERPROFILE, 'vcpkg', 'installed', 'x64-windows', 'lib', 'utf8_validity.lib')\")",
            "<!(node -p \"require('path').join(process.env.USERPROFILE, 'vcpkg', 'installed', 'x64-windows', 'lib', 'utf8_range.lib')\")"
          ],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1,
              "Optimization": 3,
              "InlineFunctionExpansion": 2,
              "FavorSizeOrSpeed": 1,
              "StringPooling": "true",
              "OmitFramePointers": "true",
              "AdditionalOptions": [
                "/GL",
                "/Gw",
                "/Gy",
                "/Oi",
                "/Ot"
              ]
            },
            "VCLinkerTool": {
              "LinkTimeCodeGeneration": 1,
              "OptimizeReferences": 2,
              "EnableCOMDATFolding": 2,
              "AdditionalOptions": [
                "/LTCG",
                "/OPT:REF",
                "/OPT:ICF"
              ]
            }
          }
        }],
        [ "OS=='mac'", {
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "CLANG_CXX_LANGUAGE_STANDARD": "c++17",
            "GCC_OPTIMIZATION_LEVEL": "3",
            "DEAD_CODE_STRIPPING": "YES",
            "OTHER_CPLUSPLUSFLAGS": [
              "-O3",
              "-flto",
              "-ffunction-sections",
              "-fdata-sections",
              "-fstrict-aliasing"
            ],
            "OTHER_LDFLAGS": [
              "-flto",
              "-Wl,-dead_strip"
            ]
          }
        }],
        [ "OS!='win' and OS!='mac'", {
          "cflags_cc": [
            "-std=c++17",
            "-O3",
            "-flto",
            "-fexceptions",
            "-ffunction-sections",
            "-fdata-sections",
            "-fstrict-aliasing"
          ],
          "ldflags": [
            "-flto",
            "-Wl,--gc-sections",
            "-Wl,-O2"
          ]
        }]
      ]
    }
  ]
}
