# Meshanics MCU agent SDK - Zephyr module build wiring.
#
# The verified on-device implementation is being extracted from the Meshanics
# monorepo (agent/mcu/{verify,ota} + the plat_* seam) into lib/ here - see
# lib/README.md for the vendoring map. Sources are added as they land.

if(CONFIG_MESHANICS_AGENT)
  zephyr_library()
  zephyr_include_directories(include)

  zephyr_library_sources(
    lib/meshanics_agent.c
  )

  # Extracted modules (uncomment as each is vendored in):
  # zephyr_library_sources(
  #   lib/verify/manifest_verify.c
  #   lib/verify/ed25519_fiat.c
  #   lib/ota/ota.c
  #   lib/plat/plat_net.c
  #   lib/plat/plat_mcuboot.c
  #   lib/plat/plat_counter.c
  # )
endif()
