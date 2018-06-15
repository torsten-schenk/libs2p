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

static void update_buffer(
		s2p_buffer_t *self,
		const char *string)
{
	size_t n = strlen(string);
	size_t off = self->roff;
	s2p_chunk_t *chunk = self->rchunk;
	CU_ASSERT_EQUAL(n, self->fill);

	while(n) {
		size_t cur = S2P_MIN(n, chunk->owner->size - off);
		memcpy(chunk->data + off, string, cur);
		string += cur;
		off = 0;
		chunk = chunk->next;
		n -= cur;
	}
}

static void dump_buffer(
		const s2p_buffer_t *self)
{
	s2p_chunk_t *c;
	printf("----------------------------------------- BUFFER DUMP -----------------------------------------\n");
	printf("rchunk=%p roff=%zu wchunk=%p woff=%zu fill=%zu\n", self->rchunk, self->roff, self->wchunk, self->woff, self->fill);

	for(c = self->rchunk; c; c = c->next) {
		printf("\nchunk %p: owner=%p size=%zu next=%p\n", c, c->owner, c->owner->size, c->next);
		hexdump(c->data, c->owner->size);
	}
	printf("-----------------------------------------------------------------------------------------------\n");
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
	update_buffer(&buffer, "4321");
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->data + 0, "4321", 4), 0);
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
	update_buffer(&buffer, "4321");
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->data + 4, "432", 3), 0);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->next->data + 0, "1", 1), 0);
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
	update_buffer(&buffer, "fedcba987654321");
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->data + 4, "fed", 3), 0);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->next->data + 0, "cba9876", 7), 0);
	CU_ASSERT_EQUAL(memcmp(buffer.rchunk->next->next->data + 0, "54321", 5), 0);
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

static void test1_cpy()
{
	s2p_buffer_t source;
	s2p_buffer_t target;

	/* start at offset 0 and use 1 full chunk (rw) */
	make_buffer(&source, pool4, 0, "1234", false);
	s2p_buffer_cpy(&target, &source, -1);
	CU_ASSERT_PTR_NULL(target.wchunk);
	CU_ASSERT_PTR_EQUAL(target.rchunk, source.rchunk);
	CU_ASSERT_PTR_EQUAL(target.roff, source.roff);
	CU_ASSERT_EQUAL(source.fill, target.fill);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 2);
	CU_ASSERT_EQUAL(target.rchunk->refcnt, 2);
	CU_ASSERT_EQUAL(target.rchunk->next->refcnt, 1);

	s2p_buffer_destroy(&target);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 2);
	CU_ASSERT_EQUAL(target.rchunk->refcnt, 1);
	CU_ASSERT_EQUAL(target.rchunk->next->refcnt, 1);
	s2p_buffer_destroy(&source);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 0);

	/* start at offset 0 and use 1 full chunk (ro) */
	make_buffer(&source, pool4, 0, "1234", true);
	s2p_buffer_cpy(&target, &source, -1);
	CU_ASSERT_PTR_NULL(target.wchunk);
	CU_ASSERT_PTR_EQUAL(target.rchunk, source.rchunk);
	CU_ASSERT_PTR_EQUAL(target.roff, source.roff);
	CU_ASSERT_EQUAL(source.fill, target.fill);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 1);
	CU_ASSERT_EQUAL(target.rchunk->refcnt, 2);

	s2p_buffer_destroy(&target);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 1);
	CU_ASSERT_EQUAL(target.rchunk->refcnt, 1);
	s2p_buffer_destroy(&source);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 0);

	/* start at offset 2 and use 2 chunks (rw) */
	make_buffer(&source, pool4, 2, "1234", false);
	s2p_buffer_cpy(&target, &source, -1);
	CU_ASSERT_PTR_NULL(target.wchunk);
	CU_ASSERT_PTR_EQUAL(target.rchunk, source.rchunk);
	CU_ASSERT_PTR_EQUAL(target.roff, source.roff);
	CU_ASSERT_EQUAL(source.fill, target.fill);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 2);
	CU_ASSERT_EQUAL(target.rchunk->refcnt, 2);
	CU_ASSERT_EQUAL(target.rchunk->next->refcnt, 2);

	s2p_buffer_destroy(&target);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 2);
	CU_ASSERT_EQUAL(target.rchunk->refcnt, 1);
	CU_ASSERT_EQUAL(target.rchunk->next->refcnt, 1);
	s2p_buffer_destroy(&source);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 0);

	/* start at offset 2 and use 2 chunks (ro) */
	make_buffer(&source, pool4, 2, "1234", true);
	s2p_buffer_cpy(&target, &source, -1);
	CU_ASSERT_PTR_NULL(target.wchunk);
	CU_ASSERT_PTR_EQUAL(target.rchunk, source.rchunk);
	CU_ASSERT_PTR_EQUAL(target.roff, source.roff);
	CU_ASSERT_EQUAL(source.fill, target.fill);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 2);
	CU_ASSERT_EQUAL(target.rchunk->refcnt, 2);
	CU_ASSERT_EQUAL(target.rchunk->next->refcnt, 2);

	s2p_buffer_destroy(&target);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 2);
	CU_ASSERT_EQUAL(target.rchunk->refcnt, 1);
	CU_ASSERT_EQUAL(target.rchunk->next->refcnt, 1);
	s2p_buffer_destroy(&source);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 0);
}

static void test1_cmp_data()
{
	s2p_buffer_t a;

	make_buffer(&a, pool4, 2, "12345678", false);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "12345678", 8), 0);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "1234567", 7), 0);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "1234", 4), 0);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "123", 3), 0);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "12", 2), 0);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "", 0), 0);

	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "02345678", 8), 1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "10345678", 8), 1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "12045678", 8), 1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "12305678", 8), 1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "12340678", 8), 1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "12345078", 8), 1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "12345608", 8), 1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "12345670", 8), 1);

	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "a2345678", 8), -1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "1a345678", 8), -1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "12a45678", 8), -1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "123a5678", 8), -1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "1234a678", 8), -1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "12345a78", 8), -1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "123456a8", 8), -1);
	CU_ASSERT_EQUAL(s2p_buffer_cmp_data(&a, "1234567a", 8), -1);

	s2p_buffer_destroy(&a);
}

static void test1_cmp()
{
	s2p_buffer_t a;
	s2p_buffer_t b;
	char seq[27];
	int i;

	strcpy(seq, "abcdefghijklmnopqrstuvwxyz");
	make_buffer(&a, pool4, 2, seq, true);
	make_buffer(&b, pool7, 4, seq, true);
	CU_ASSERT_EQUAL(s2p_buffer_cmp(&a, &b, -1), 0);
	CU_ASSERT_EQUAL(s2p_buffer_cmp(&b, &a, -1), 0);
	for(i = 0; i < 26; i++) {
		char c = seq[i];
		seq[i] = ' ';
		update_buffer(&a, seq);
		CU_ASSERT_EQUAL(s2p_buffer_cmp(&a, &b, -1), -1);
		CU_ASSERT_EQUAL(s2p_buffer_cmp(&b, &a, -1), 1);
		seq[i] = c;
		update_buffer(&a, seq);

		seq[i] = ' ';
		update_buffer(&b, seq);
		CU_ASSERT_EQUAL(s2p_buffer_cmp(&a, &b, -1), 1);
		CU_ASSERT_EQUAL(s2p_buffer_cmp(&b, &a, -1), -1);
		seq[i] = c;
		update_buffer(&b, seq);
	}

	s2p_buffer_destroy(&b);
	s2p_buffer_destroy(&a);
}

static int test2_init()
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

static int test2_cleanup()
{
	testpool_destroy(pool7);
	testpool_destroy(pool4);
	return CUE_SUCCESS;
}

static void test2_begin()
{
	s2p_buffer_t buffer;
	s2p_write_t write;

	/* read-only buffer */
	make_buffer(&buffer, pool7, 0, "1", true);
	CU_ASSERT_EQUAL(s2p_write_begin(&write, &buffer, pool7), -1);
	CU_ASSERT_EQUAL(errno, EACCES);
	destroy_buffer(&buffer);

	/* null buffer */
	s2p_buffer_init(&buffer);
	CU_ASSERT_EQUAL(s2p_write_begin(&write, &buffer, pool7), 0);
	CU_ASSERT_EQUAL(((testpool_t*)pool7)->n_alloc, 1);
	destroy_buffer(&buffer);

	/* read-write buffer */
	make_buffer(&buffer, pool7, 0, "1", false);
	CU_ASSERT_EQUAL(s2p_write_begin(&write, &buffer, pool7), 0);
	CU_ASSERT_EQUAL(((testpool_t*)pool7)->n_alloc, 1);
	destroy_buffer(&buffer);
}

static void test2_reserve()
{
	s2p_buffer_t buffer;
	s2p_write_t write;

	make_buffer(&buffer, pool4, 2, "123", false);
	s2p_write_begin(&write, &buffer, pool4);
	CU_ASSERT_EQUAL(write.eoff, 1);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 2);
	
	s2p_write_reserve(&write, 2, SEEK_SET);
	CU_ASSERT_EQUAL(write.size, 2);
	CU_ASSERT_EQUAL(write.eoff, 3);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 2);

	s2p_write_reserve(&write, 3, SEEK_SET);
	CU_ASSERT_EQUAL(write.size, 3);
	CU_ASSERT_EQUAL(write.eoff, 0);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 3);

	s2p_write_reserve(&write, 5, SEEK_END);
	CU_ASSERT_EQUAL(write.size, 8);
	CU_ASSERT_EQUAL(write.eoff, 1);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 4);

	destroy_buffer(&buffer);
}

static void test2_abort()
{
	s2p_buffer_t buffer;
	s2p_write_t write;
	s2p_chunk_t *chunk;
	size_t off;

	make_buffer(&buffer, pool4, 2, "123", false);
	chunk = buffer.wchunk;
	off = buffer.woff;
	s2p_write_begin(&write, &buffer, pool4);
	CU_ASSERT_EQUAL(write.eoff, 1);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 2);
	
	s2p_write_reserve(&write, 8, SEEK_SET);
	CU_ASSERT_EQUAL(write.size, 8);
	CU_ASSERT_EQUAL(write.eoff, 1);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 4);

	s2p_write_abort(&write);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 2);
	CU_ASSERT_PTR_EQUAL(buffer.wchunk, chunk);
	CU_ASSERT_EQUAL(buffer.woff, off);
	CU_ASSERT_EQUAL(buffer.fill, 3);
	s2p_buffer_destroy(&buffer);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 0);
}

static void test2_commit()
{
	s2p_buffer_t buffer;
	s2p_write_t write;
	s2p_chunk_t *chunk;
	size_t off;

	make_buffer(&buffer, pool4, 2, "123", false);
	s2p_write_begin(&write, &buffer, pool4);
	CU_ASSERT_EQUAL(write.eoff, 1);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 2);
	
	s2p_write_reserve(&write, 8, SEEK_SET);
	CU_ASSERT_EQUAL(write.size, 8);
	CU_ASSERT_EQUAL(write.eoff, 1);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 4);
	chunk = write.echunk;
	off = write.eoff;

	s2p_write_commit(&write);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 4);
	CU_ASSERT_PTR_EQUAL(buffer.wchunk, chunk);
	CU_ASSERT_EQUAL(buffer.woff, off);
	CU_ASSERT_EQUAL(buffer.fill, 11);
	s2p_buffer_destroy(&buffer);
	CU_ASSERT_EQUAL(((testpool_t*)pool4)->n_alloc, 0);
}

static void assert_wpos(
		s2p_write_t *self,
		size_t pos)
{
	size_t n = pos;
	s2p_chunk_t *chunk = self->buffer->wchunk;
	size_t off = self->buffer->woff;
	CU_ASSERT_EQUAL(pos, self->pos);
	CU_ASSERT(self->pos <= self->size);
	while(n) {
		size_t cur = S2P_MIN(n, chunk->owner->size - off);
		n -= cur;
		off += cur;
		if(off == chunk->owner->size) {
			chunk = chunk->next;
			off = 0;
		}
	}
	CU_ASSERT_PTR_EQUAL(self->chunk, chunk);
	CU_ASSERT_EQUAL(self->off, off);
	CU_ASSERT_PTR_EQUAL(self->di, chunk->data + off);
	CU_ASSERT_EQUAL(self->n, S2P_MIN(self->size - self->pos, chunk->owner->size - off));
}

static void test2_seek()
{
	/* legend:
	 *   - unused
	 *   R read area
	 *   p current write position
	 *   u upper position (first byte after write area)
	 *   s seek target
	 *   i invalid seek target
	 *   . write area */

	s2p_buffer_t buffer;
	s2p_write_t write;
	make_buffer(&buffer, pool7, 1, "AB", false);
	s2p_write_begin(&write, &buffer, pool7);

	/* case: |-RR[psu]---| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 0, SEEK_SET), 0);
	assert_wpos(&write, 0);
	/* case: |-RR[pu]i--| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 1, SEEK_SET), -1);
	CU_ASSERT_EQUAL(write.pos, 0);

	s2p_write_reserve(&write, 1, SEEK_END);
	/* case: |-RR[ps]u--|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 0, SEEK_SET), 0);
	assert_wpos(&write, 0);
	/* case: |-RRp[su]--|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 1, SEEK_SET), 0);
	assert_wpos(&write, 1);
	/* case: |-RRs[pu]--|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 0, SEEK_SET), 0);
	assert_wpos(&write, 0);

	s2p_write_reserve(&write, 3, SEEK_END);
	/* case: |-RRp..s|u------|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 3, SEEK_SET), 0);
	assert_wpos(&write, 3);
	/* case: |-RR...p|[su]------|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 4, SEEK_SET), 0);
	assert_wpos(&write, 4);
	/* case: |-RRs...|[pu]------|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 0, SEEK_SET), 0);
	assert_wpos(&write, 0);

	s2p_write_reserve(&write, 6, SEEK_END);
	/* case: |-RRp...|......u|i */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 11, SEEK_SET), -1);
	assert_wpos(&write, 0);
	/* case: |-RRp...|......[su]|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 10, SEEK_SET), 0);
	assert_wpos(&write, 10);
	/* case: |-RR...s|......[pu]|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 3, SEEK_SET), 0);
	assert_wpos(&write, 3);
	/* case: |-RR...p|...s..u|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 7, SEEK_SET), 0);
	assert_wpos(&write, 7);

	s2p_write_reserve(&write, 7, SEEK_END);
	/* case: |-RR....|...p...|......u|i */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 18, SEEK_SET), -1);
	assert_wpos(&write, 7);
	/* case: |-RR..s.|...p...|......u| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 2, SEEK_SET), 0);
	assert_wpos(&write, 2);
	/* case: |-RR..p.|.......|..s...u| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 13, SEEK_SET), 0);
	assert_wpos(&write, 13);
	/* case: |-RR....|...s...|..p...u| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 7, SEEK_SET), 0);
	assert_wpos(&write, 7);
	/* case: |-RR....|...p...|......[su]| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 17, SEEK_SET), 0);
	assert_wpos(&write, 17);
	/* case: |-RR..s.|.......|......[pu]| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 2, SEEK_SET), 0);
	assert_wpos(&write, 2);

	CU_ASSERT_EQUAL(s2p_write_seek(&write, 0, SEEK_END), 0);
	assert_wpos(&write, 17);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, -2, SEEK_END), 0);
	assert_wpos(&write, 15);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, -4, SEEK_END), 0);
	assert_wpos(&write, 13);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 3, SEEK_CUR), 0);
	assert_wpos(&write, 16);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, -10, SEEK_CUR), 0);
	assert_wpos(&write, 6);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, -6, SEEK_CUR), 0);
	assert_wpos(&write, 0);

	s2p_write_seek(&write, 6, SEEK_SET);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, -7, SEEK_CUR), -1);
	assert_wpos(&write, 6);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 1, SEEK_END), -1);
	assert_wpos(&write, 6);

	destroy_buffer(&buffer);
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
		ADD_TEST("s2p_buffer_cpy", test1_cpy);
		ADD_TEST("s2p_buffer_cmp_data", test1_cmp_data);
		ADD_TEST("s2p_buffer_cmp", test1_cmp);
	END_SUITE;
	BEGIN_SUITE("Buffer write", test2_init, test2_cleanup);
		ADD_TEST("s2p_write_begin", test2_begin);
		ADD_TEST("s2p_write_reserve", test2_reserve);
		ADD_TEST("s2p_write_abort", test2_abort);
		ADD_TEST("s2p_write_commit", test2_commit);
		ADD_TEST("s2p_write_seek + implicit s2p_write_update", test2_seek);
	END_SUITE;

	return CUE_SUCCESS;
}

