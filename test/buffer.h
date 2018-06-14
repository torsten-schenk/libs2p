#include "test.h"

typedef struct testpool testpool_t;

struct testpool {
	s2p_pool_t _;
	size_t n_alloc;
};

static s2p_chunk_t *testpool_acquire(
		s2p_pool_t *pool_)
{
	testpool_t *pool = (testpool_t*)pool_;
	s2p_chunk_t *chunk = malloc(sizeof(s2p_chunk_t) + pool->_.size);
	if(!chunk)
		return NULL;
	chunk->owner = pool_;
	chunk->refcnt = 1;
	chunk->next = NULL;
	pool->n_alloc++;
	return chunk;
}

static void testpool_release(
		s2p_chunk_t *chunk)
{
	testpool_t *pool = (testpool_t*)chunk->owner;
	pool->n_alloc--;
	free(chunk);
}

static s2p_pool_t *testpool_new(
		size_t size)
{
	testpool_t *self = malloc(sizeof(testpool_t));
	if(!self)
		return NULL;
	memset(self, 0, sizeof(testpool_t));
	self->_.acquire = testpool_acquire;
	self->_.release = testpool_release;
	self->_.size = size;
	return (s2p_pool_t*)self;
}

static void testpool_destroy(
		s2p_pool_t *self_)
{
	testpool_t *self = (testpool_t*)self_;
	free(self);
}

static void make_buffer(
		s2p_buffer_t *self,
		s2p_pool_t *pool,
		size_t roff,
		const char *data,
		bool ro)
{
	s2p_chunk_t *prev = NULL;
	s2p_chunk_t *chunk = NULL;
	size_t off = roff;
	const char *si = data;
	size_t size = strlen(data);
	memset(self, 0, sizeof(s2p_buffer_t));
	self->fill = size;
	self->roff = roff;
	while(size) {
		size_t cur = S2P_MIN(size, pool->size - off);
		if(!chunk) {
			chunk = pool->acquire(pool);
			if(prev)
				prev->next = chunk;
			else
				self->rchunk = chunk;
		}
		if(si) {
			memcpy(chunk->data + off, si, cur);
			si += cur;
		}
		size -= cur;
		off += cur;
		if(off == pool->size) {
			off = 0;
			prev = chunk;
			chunk = NULL;
		}

	}
	if(!ro) {
		if(!chunk) {
			chunk = pool->acquire(pool);
			if(prev)
				prev->next = chunk;
			else
				self->rchunk = chunk;
		}
		self->wchunk = chunk;
		self->woff = off;
	}
}

static void destroy_buffer(
		s2p_buffer_t *self)
{
	s2p_chunk_t *chunk = self->rchunk;
	while(chunk) {
		s2p_chunk_t *prev = chunk;
		chunk = chunk->next;
		s2p_chunk_unref(prev);
	}
}

static s2p_pool_t *pool4;
static s2p_pool_t *pool7;

static int test0_init()
{
	return CUE_SUCCESS;
}

static int test0_cleanup()
{
	return CUE_SUCCESS;
}

static void test0_pool()
{
	testpool_t *pool = (testpool_t*)testpool_new(4);
	s2p_chunk_t *chunks[8];
	CU_ASSERT_EQUAL(pool->_.size, 4);
	CU_ASSERT_EQUAL(pool->n_alloc, 0);

	chunks[0] = pool->_.acquire((s2p_pool_t*)pool);
	CU_ASSERT_EQUAL(chunks[0]->refcnt, 1);
	CU_ASSERT_EQUAL(pool->n_alloc, 1);
	CU_ASSERT_PTR_EQUAL(chunks[0]->owner, pool);
	CU_ASSERT_PTR_NULL(chunks[0]->next);

	chunks[1] = pool->_.acquire((s2p_pool_t*)pool);
	CU_ASSERT_EQUAL(chunks[1]->refcnt, 1);
	CU_ASSERT_EQUAL(pool->n_alloc, 2);
	CU_ASSERT_PTR_EQUAL(chunks[1]->owner, pool);
	CU_ASSERT_PTR_NULL(chunks[1]->next);

	chunks[2] = pool->_.acquire((s2p_pool_t*)pool);
	CU_ASSERT_EQUAL(chunks[2]->refcnt, 1);
	CU_ASSERT_EQUAL(pool->n_alloc, 3);
	CU_ASSERT_PTR_EQUAL(chunks[2]->owner, pool);
	CU_ASSERT_PTR_NULL(chunks[2]->next);
	s2p_chunk_ref(chunks[2]);
	CU_ASSERT_EQUAL(chunks[2]->refcnt, 2);
	s2p_chunk_unref(chunks[2]);
	CU_ASSERT_EQUAL(pool->n_alloc, 3);
	CU_ASSERT_EQUAL(chunks[2]->refcnt, 1);
	s2p_chunk_unref(chunks[2]);
	CU_ASSERT_EQUAL(pool->n_alloc, 2);

	pool->_.release(chunks[1]);
	CU_ASSERT_EQUAL(pool->n_alloc, 1);
	pool->_.release(chunks[0]);
	CU_ASSERT_EQUAL(pool->n_alloc, 0);
	testpool_destroy((s2p_pool_t*)pool);
}

static void test0_make_buffer()
{
	s2p_buffer_t buffer;
	testpool_t *pool = (testpool_t*)testpool_new(7);

	make_buffer(&buffer, (s2p_pool_t*)pool, 0, "", true);
	CU_ASSERT_EQUAL(pool->n_alloc, 0);
	CU_ASSERT_PTR_NULL(buffer.wchunk);
	CU_ASSERT_PTR_NULL(buffer.rchunk);
	CU_ASSERT_EQUAL(s2p_buffer_status(&buffer), S2P_BUFFER_NULL);
	destroy_buffer(&buffer);

	make_buffer(&buffer, (s2p_pool_t*)pool, 0, "", false);
	CU_ASSERT_EQUAL(pool->n_alloc, 1);
	CU_ASSERT_PTR_NOT_NULL(buffer.wchunk);
	CU_ASSERT_PTR_NOT_NULL(buffer.rchunk);
	CU_ASSERT_PTR_EQUAL(buffer.rchunk, buffer.wchunk);
	CU_ASSERT_EQUAL(s2p_buffer_status(&buffer), S2P_BUFFER_EMPTY);
	destroy_buffer(&buffer);

	make_buffer(&buffer, (s2p_pool_t*)pool, 0, "1234", true);
	CU_ASSERT_EQUAL(pool->n_alloc, 1);
	CU_ASSERT_PTR_NULL(buffer.wchunk);
	CU_ASSERT_PTR_NOT_NULL(buffer.rchunk);
	CU_ASSERT_EQUAL(buffer.fill, 4);
	CU_ASSERT_EQUAL(buffer.roff, 0);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->data + 0, "1234", 4), 0);
	CU_ASSERT_EQUAL(s2p_buffer_status(&buffer), S2P_BUFFER_NOT_EMPTY | S2P_BUFFER_RDONLY);
	destroy_buffer(&buffer);
	CU_ASSERT_EQUAL(pool->n_alloc, 0);

	make_buffer(&buffer, (s2p_pool_t*)pool, 2, "1234", true);
	CU_ASSERT_EQUAL(pool->n_alloc, 1);
	CU_ASSERT_PTR_NOT_NULL(buffer.rchunk);
	CU_ASSERT_EQUAL(buffer.fill, 4);
	CU_ASSERT_EQUAL(buffer.roff, 2);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->data + 2, "1234", 4), 0);
	CU_ASSERT_EQUAL(s2p_buffer_status(&buffer), S2P_BUFFER_NOT_EMPTY | S2P_BUFFER_RDONLY);
	destroy_buffer(&buffer);
	CU_ASSERT_EQUAL(pool->n_alloc, 0);

	make_buffer(&buffer, (s2p_pool_t*)pool, 2, "1234", false);
	CU_ASSERT_EQUAL(pool->n_alloc, 1);
	CU_ASSERT_PTR_NOT_NULL(buffer.rchunk);
	CU_ASSERT_PTR_EQUAL(buffer.rchunk, buffer.wchunk);
	CU_ASSERT_EQUAL(buffer.fill, 4);
	CU_ASSERT_EQUAL(buffer.roff, 2);
	CU_ASSERT_EQUAL(buffer.woff, 6);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->data + 2, "1234", 4), 0);
	CU_ASSERT_EQUAL(s2p_buffer_status(&buffer), S2P_BUFFER_NOT_EMPTY);
	destroy_buffer(&buffer);
	CU_ASSERT_EQUAL(pool->n_alloc, 0);

	make_buffer(&buffer, (s2p_pool_t*)pool, 3, "1234", true);
	CU_ASSERT_EQUAL(pool->n_alloc, 1);
	CU_ASSERT_PTR_NOT_NULL(buffer.rchunk);
	CU_ASSERT_EQUAL(buffer.fill, 4);
	CU_ASSERT_EQUAL(buffer.roff, 3);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->data + 3, "1234", 4), 0);
	CU_ASSERT_EQUAL(s2p_buffer_status(&buffer), S2P_BUFFER_NOT_EMPTY | S2P_BUFFER_RDONLY);
	destroy_buffer(&buffer);
	CU_ASSERT_EQUAL(pool->n_alloc, 0);

	make_buffer(&buffer, (s2p_pool_t*)pool, 3, "1234", false);
	CU_ASSERT_EQUAL(pool->n_alloc, 2);
	CU_ASSERT_PTR_NOT_NULL(buffer.rchunk);
	CU_ASSERT_PTR_NOT_NULL(buffer.wchunk);
	CU_ASSERT_PTR_EQUAL(buffer.rchunk->next, buffer.wchunk);
	CU_ASSERT_EQUAL(buffer.fill, 4);
	CU_ASSERT_EQUAL(buffer.roff, 3);
	CU_ASSERT_EQUAL(buffer.woff, 0);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->data + 3, "1234", 4), 0);
	CU_ASSERT_EQUAL(s2p_buffer_status(&buffer), S2P_BUFFER_NOT_EMPTY);
	destroy_buffer(&buffer);
	CU_ASSERT_EQUAL(pool->n_alloc, 0);

	make_buffer(&buffer, (s2p_pool_t*)pool, 4, "1234", true);
	CU_ASSERT_EQUAL(pool->n_alloc, 2);
	CU_ASSERT_PTR_NOT_NULL(buffer.rchunk);
	CU_ASSERT_EQUAL(buffer.fill, 4);
	CU_ASSERT_EQUAL(buffer.roff, 4);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->data + 4, "123", 3), 0);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->next->data + 0, "4", 1), 0);
	CU_ASSERT_EQUAL(s2p_buffer_status(&buffer), S2P_BUFFER_NOT_EMPTY | S2P_BUFFER_RDONLY);
	destroy_buffer(&buffer);
	CU_ASSERT_EQUAL(pool->n_alloc, 0);

	make_buffer(&buffer, (s2p_pool_t*)pool, 4, "123456789abcdef", true);
	CU_ASSERT_EQUAL(pool->n_alloc, 3);
	CU_ASSERT_PTR_NOT_NULL(buffer.rchunk);
	CU_ASSERT_EQUAL(buffer.fill, 15);
	CU_ASSERT_EQUAL(buffer.roff, 4);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->data + 4, "123", 3), 0);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->next->data + 0, "456789a", 7), 0);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->next->next->data + 0, "bcdef", 5), 0);
	CU_ASSERT_EQUAL(s2p_buffer_status(&buffer), S2P_BUFFER_NOT_EMPTY | S2P_BUFFER_RDONLY);
	destroy_buffer(&buffer);
	CU_ASSERT_EQUAL(pool->n_alloc, 0);

	testpool_destroy((s2p_pool_t*)pool);
}

static int test1_init()
{
	pool4 = testpool_new(4);
	if(!pool4)
		goto error_1;
	pool7 = testpool_new(7);
	if(!pool7)
		goto error_2;
	return CUE_SUCCESS;

error_2:
	testpool_destroy(pool4);
error_1:
	return CUE_SINIT_FAILED;
}

static int test1_cleanup()
{
	testpool_destroy(pool7);
	testpool_destroy(pool4);
	return CUE_SUCCESS;
}

static void test1_copy1()
{
	s2p_buffer_t buffer;
}

static int setup_tests()
{
	CU_pSuite suite;
	CU_pTest test;

	BEGIN_SUITE("Test-internal functions", test0_init, test0_cleanup);
		ADD_TEST("pool acquire/release", test0_pool);
		ADD_TEST("make buffer + basic library functions", test0_make_buffer);
	END_SUITE;
	BEGIN_SUITE("Buffer functions", test1_init, test1_cleanup);
		ADD_TEST("copy buffer", test1_copy1);
	END_SUITE;

	return CUE_SUCCESS;
}

