# Meshanics MCU agent SDK - Zephyr module build.

if(CONFIG_MESHANICS_AGENT)
  zephyr_library()
  zephyr_include_directories(include)

  zephyr_library_sources(
    lib/meshanics_agent.c
  )

  # Agent components (added as each lands):
  # zephyr_library_sources(
  #   lib/verify/manifest_verify.c
  #   lib/verify/ed25519.c
  #   lib/ota/ota.c
  #   lib/plat/plat_net.c
  #   lib/plat/plat_mcuboot.c
  #   lib/plat/plat_counter.c
  # )
endif()
