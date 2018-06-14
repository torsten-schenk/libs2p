#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <stdint.h>

#include "../include/types.h"

#define S2P_REF(CNT) __atomic_fetch_add(&(CNT), 1, __ATOMIC_SEQ_CST)
#define S2P_UNREF(CNT) __atomic_sub_fetch(&(CNT), 1, __ATOMIC_SEQ_CST)
#define S2P_MIN(X, Y) ((X) < (Y) ? (X) : (Y))

