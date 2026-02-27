# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

src += files(
  'bridge.c',
  'fdb.c',
  'flood.c',
  'l2_stats.c',
  'mcast_snooping.c',
  'storm_control.c',
  'vxlan.c',
)

inc += include_directories('.')

tests += [
  { 'sources': files('mcast_snooping_test.c', 'mcast_snooping.c'), 'link_args': [] },
  { 'sources': files('storm_control_test.c', 'storm_control.c'),
    'link_args': ['-Wl,--wrap=rte_rdtsc', '-Wl,--wrap=rte_meter_trtcm_profile_config',
                  '-Wl,--wrap=rte_meter_trtcm_config'],
    'c_args': ['-D__GROUT_UNIT_TEST__'] },
]
