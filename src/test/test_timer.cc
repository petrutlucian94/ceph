/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2023 Cloudbase Solutions
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

#include "common/ceph_argparse.h"
#include "common/ceph_timer.h"
#include "common/debug.h"
#include "common/dout.h"

#include "global/global_init.h"

#include "gtest/gtest.h"

#define dout_context g_ceph_context
#define dout_subsys ceph_subsys_timer
#undef dout_prefix
#define dout_prefix *_dout << " ceph_test_timer "

#define TICK_INTERVAL_S 0.00004
#define DURATION_S 30

template<typename	TC>
void tick(ceph::timer<TC>* t,
					typename TC::time_point deadline,
					bool* test_finished) {
	if (TC::now() > deadline) {
		dout(0) << "Test finished successfully, exiting." << dendl;
		*test_finished = true;
	} else {
		derr << "Time left: " << deadline - TC::now() << dendl;
	}
	t->reschedule_me(ceph::make_timespan(TICK_INTERVAL_S));
}

TEST(TimerLoopTest, timer_loop) {
	ceph::timer<ceph::coarse_mono_clock> t;
	bool test_finished = false;

	t.add_event(
		ceph::make_timespan(TICK_INTERVAL_S),
		&tick<ceph::coarse_mono_clock>,
		&t,
		ceph::coarse_mono_clock::now() + std::chrono::seconds(DURATION_S),
		&test_finished);

	dout(0) << "Waiting " << DURATION_S	+ 5 << "s." << dendl;
	std::this_thread::sleep_for(std::chrono::seconds(DURATION_S	+ 2));

	ASSERT_TRUE(test_finished)
			<< "The timer job didn't complete, it probably hanged.";
}

int main(int argc, char **argv) {
	auto args = argv_to_vec(argc, argv);

	auto cct = global_init(
		NULL, args, CEPH_ENTITY_TYPE_CLIENT,
		CODE_ENVIRONMENT_UTILITY,
		CINIT_FLAG_NO_DEFAULT_CONFIG_FILE);
	common_init_finish(g_ceph_context);

	::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
