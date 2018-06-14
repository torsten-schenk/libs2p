#pragma once

#include <CUnit/Basic.h>
#include <stdbool.h>

#define ADD_TEST(NAME, FN) \
	do {\
		test = CU_add_test(suite, NAME, FN); \
		if(test == NULL) \
			return CU_get_error(); \
	} while(false)

#define BEGIN_SUITE(NAME, INIT, CLEANUP) \
	do { \
		suite = CU_add_suite(NAME, INIT, CLEANUP); \
		if(suite == NULL) \
			return CU_get_error(); \
	} while(false)

#define END_SUITE

static int setup_tests();

int main(
		int argn,
		char **argv)
{
	int ret;
	(void)argn;
	(void)argv;

	ret = CU_initialize_registry();
	if(ret != CUE_SUCCESS) {
		printf("Error initializing CUnit.\n");
		goto error_1;
	}

	ret = setup_tests();
	if(ret != CUE_SUCCESS) {
		printf("Error setting up tests.\n");
		goto error_2;
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	ret = CU_get_error();

error_2:
	CU_cleanup_registry();
error_1:
	return ret;
}

