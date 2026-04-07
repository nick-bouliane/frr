# SPDX-License-Identifier: GPL-2.0-or-later
import frrtest


class TestStreamSpscRing(frrtest.TestMultiOut):
    program = "./test_stream_spsc_ring"


TestStreamSpscRing.exit_cleanly()
