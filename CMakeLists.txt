# Meshanics MCU agent SDK - Zephyr module build.
#
# The manifest verifier (lib/verify) and its vendored crypto (Fiat Ed25519 +
# tinycrypt SHA-512) are the exact code proven against the Go reference by the
# host conformance test; the OTA decision logic (lib/ota) is host-tested too. The
# platform layer (lib/plat) and provisioning/enrollment (lib/provision) integrate
# them against Zephyr networking, MCUboot, and NVS.

if(CONFIG_MESHANICS_AGENT)
  zephyr_library()

  # Public API for the integrator's application.
  zephyr_include_directories(include)

  # Internal headers shared across the library's own sources. APPLICATION_SOURCE_DIR
  # is on the path so provisioning.c can find the integrator's (dev) provisioning
  # header; if it is absent the agent compiles and reports "not provisioned".
  zephyr_library_include_directories(
    lib/verify
    lib/ota
    lib/plat
    lib/provision
    lib/verify/third_party/fiat
    lib/verify/third_party/tinycrypt/include
    ${APPLICATION_SOURCE_DIR}
  )

  zephyr_library_sources(
    lib/meshanics_agent.c

    lib/verify/manifest_verify.c
    lib/verify/ed25519_fiat.c
    lib/ota/ota.c

    lib/plat/plat_net.c
    lib/plat/plat_mcuboot.c
    lib/plat/plat_counter.c
    lib/plat/plat_store.c

    lib/provision/provisioning.c
    lib/provision/identity.c
    lib/provision/enroll.c
    lib/provision/claim_proto.c

    lib/verify/third_party/fiat/curve25519.c
    lib/verify/third_party/tinycrypt/source/sha512.c
    lib/verify/third_party/tinycrypt/source/utils.c
  )

  # Vendored third-party crypto: don't let its warnings fail the build.
  set_source_files_properties(
    lib/verify/third_party/fiat/curve25519.c
    lib/verify/third_party/tinycrypt/source/sha512.c
    lib/verify/third_party/tinycrypt/source/utils.c
    PROPERTIES COMPILE_OPTIONS "-w"
  )
endif()
