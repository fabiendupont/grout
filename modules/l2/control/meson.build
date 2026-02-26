# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Robin Jarry

src += files(
  'bridge.c',
  'fdb.c',
  'flood.c',
  'l2_stats.c',
  'mcast_snooping.c',
  'vxlan.c',
)

inc += include_directories('.')

tests += [
  { 'sources': files('mcast_snooping_test.c', 'mcast_snooping.c'), 'link_args': [] },
]
