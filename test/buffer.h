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

#define ASSERT_WPOS(SELF, POS) \
	do {\
		size_t n = POS; \
		s2p_chunk_t *chunk = (SELF)->buffer->wchunk; \
		size_t off = (SELF)->buffer->woff; \
		CU_ASSERT_EQUAL(POS, (SELF)->pos); \
		CU_ASSERT((SELF)->pos <= (SELF)->size); \
		while(n) { \
			size_t cur = S2P_MIN(n, chunk->owner->size - off); \
			n -= cur; \
			off += cur; \
			if(off == chunk->owner->size) { \
				chunk = chunk->next; \
				off = 0; \
			} \
		} \
		CU_ASSERT_PTR_EQUAL((SELF)->chunk, chunk); \
		CU_ASSERT_EQUAL((SELF)->off, off); \
		s2p_write_update((SELF)); \
		if((SELF)->size - (SELF)->pos > 0) { \
			CU_ASSERT_EQUAL((SELF)->n, S2P_MIN((SELF)->size - (SELF)->pos, chunk->owner->size - off)); \
			CU_ASSERT_PTR_EQUAL((SELF)->di, chunk->data + off); \
		} \
		else { \
			CU_ASSERT_EQUAL((SELF)->n, 0); \
		} \
	} while(false)

static void assert_chunk_data(
		s2p_chunk_t *chunk,
		...)
{
	va_list ap;
	const char *data;
	size_t i;
	va_start(ap, chunk);
	for(;;) {
		data = va_arg(ap, const char*);
		if(!data)
			break;
		CU_ASSERT_PTR_NOT_NULL_FATAL(chunk);
		for(i = 0; i < chunk->owner->size; i++) {
			CU_ASSERT(data[i] == ' ' || data[i] == chunk->data[i]);
		}
		chunk = chunk->next;
	}
	va_end(ap);
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
	ASSERT_WPOS(&write, 0);
	/* case: |-RR[pu]i--| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 1, SEEK_SET), -1);
	CU_ASSERT_EQUAL(write.pos, 0);

	s2p_write_reserve(&write, 1, SEEK_END);
	/* case: |-RR[ps]u--|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 0, SEEK_SET), 0);
	ASSERT_WPOS(&write, 0);
	/* case: |-RRp[su]--|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 1, SEEK_SET), 0);
	ASSERT_WPOS(&write, 1);
	/* case: |-RRs[pu]--|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 0, SEEK_SET), 0);
	ASSERT_WPOS(&write, 0);

	s2p_write_reserve(&write, 3, SEEK_END);
	/* case: |-RRp..s|u------|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 3, SEEK_SET), 0);
	ASSERT_WPOS(&write, 3);
	/* case: |-RR...p|[su]------|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 4, SEEK_SET), 0);
	ASSERT_WPOS(&write, 4);
	/* case: |-RRs...|[pu]------|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 0, SEEK_SET), 0);
	ASSERT_WPOS(&write, 0);

	s2p_write_reserve(&write, 6, SEEK_END);
	/* case: |-RRp...|......u|i */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 11, SEEK_SET), -1);
	ASSERT_WPOS(&write, 0);
	/* case: |-RRp...|......[su]|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 10, SEEK_SET), 0);
	ASSERT_WPOS(&write, 10);
	/* case: |-RR...s|......[pu]|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 3, SEEK_SET), 0);
	ASSERT_WPOS(&write, 3);
	/* case: |-RR...p|...s..u|*/
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 7, SEEK_SET), 0);
	ASSERT_WPOS(&write, 7);

	s2p_write_reserve(&write, 7, SEEK_END);
	/* case: |-RR....|...p...|......u|i */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 18, SEEK_SET), -1);
	ASSERT_WPOS(&write, 7);
	/* case: |-RR..s.|...p...|......u| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 2, SEEK_SET), 0);
	ASSERT_WPOS(&write, 2);
	/* case: |-RR..p.|.......|..s...u| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 13, SEEK_SET), 0);
	ASSERT_WPOS(&write, 13);
	/* case: |-RR....|...s...|..p...u| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 7, SEEK_SET), 0);
	ASSERT_WPOS(&write, 7);
	/* case: |-RR....|...p...|......[su]| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 17, SEEK_SET), 0);
	ASSERT_WPOS(&write, 17);
	/* case: |-RR..s.|.......|......[pu]| */
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 2, SEEK_SET), 0);
	ASSERT_WPOS(&write, 2);

	CU_ASSERT_EQUAL(s2p_write_seek(&write, 0, SEEK_END), 0);
	ASSERT_WPOS(&write, 17);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, -2, SEEK_END), 0);
	ASSERT_WPOS(&write, 15);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, -4, SEEK_END), 0);
	ASSERT_WPOS(&write, 13);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 3, SEEK_CUR), 0);
	ASSERT_WPOS(&write, 16);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, -10, SEEK_CUR), 0);
	ASSERT_WPOS(&write, 6);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, -6, SEEK_CUR), 0);
	ASSERT_WPOS(&write, 0);

	s2p_write_seek(&write, 6, SEEK_SET);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, -7, SEEK_CUR), -1);
	ASSERT_WPOS(&write, 6);
	CU_ASSERT_EQUAL(s2p_write_seek(&write, 1, SEEK_END), -1);
	ASSERT_WPOS(&write, 6);

	destroy_buffer(&buffer);
}

static void test2_data()
{
	s2p_buffer_t buffer;
	s2p_write_t write;

	make_buffer(&buffer, pool7, 1, "ab", false);
	s2p_write_begin(&write, &buffer, pool7);

	/* case: |-RR[wu]w--|*/
	s2p_write_str(&write, "01");
	CU_ASSERT_EQUAL(write.error, 0);
	CU_ASSERT_EQUAL(write.size, 2);
	ASSERT_WPOS(&write, 2);
	assert_chunk_data(buffer.rchunk, " ab01  ", NULL);
	s2p_write_str(&write, "23");
	assert_chunk_data(buffer.rchunk, " ab0123", "       ", NULL);
	s2p_write_str(&write, "4567");
	CU_ASSERT_EQUAL(write.size, 8);
	ASSERT_WPOS(&write, 8);
	assert_chunk_data(buffer.rchunk, " ab0123", "4567   ", NULL);
	s2p_write_str(&write, "89abcdef");
	CU_ASSERT_EQUAL(write.size, 16);
	ASSERT_WPOS(&write, 16);
	assert_chunk_data(buffer.rchunk, " ab0123", "456789a", "bcdef  ", NULL);
	s2p_write_str(&write, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	CU_ASSERT_EQUAL(write.size, 42);
	ASSERT_WPOS(&write, 42);
	assert_chunk_data(buffer.rchunk, " ab0123", "456789a", "bcdefAB", "CDEFGHI", "JKLMNOP", "QRSTUVW", "XYZ    ", NULL);

	s2p_write_seek(&write, 3, SEEK_SET);
	s2p_write_str(&write, "[]");
	CU_ASSERT_EQUAL(write.size, 42);
	ASSERT_WPOS(&write, 5);
	assert_chunk_data(buffer.rchunk, " ab012[", "]56789a", "bcdefAB", "CDEFGHI", "JKLMNOP", "QRSTUVW", "XYZ    ", NULL);

	s2p_write_seek(&write, 4, SEEK_SET);
	s2p_write_u8(&write, 0x67);
	ASSERT_WPOS(&write, 5);
	s2p_write_u16(&write, 0x6869);
	ASSERT_WPOS(&write, 7);
	s2p_write_u32(&write, 0x6a6b6c6d);
	ASSERT_WPOS(&write, 11);
	s2p_write_u64(&write, 0x6e6f707172737475);
	ASSERT_WPOS(&write, 19);

	assert_chunk_data(buffer.rchunk, " ab012[", "ghijklm", "nopqrst", "uDEFGHI", "JKLMNOP", "QRSTUVW", "XYZ    ", NULL);

	s2p_write_seek(&write, 4, SEEK_SET);
	s2p_write_set(&write, 0x2e, 24);
	CU_ASSERT_EQUAL(write.size, 42);
	ASSERT_WPOS(&write, 28);

	s2p_write_set(&write, 0x2d, 20);
	CU_ASSERT_EQUAL(write.size, 48);
	ASSERT_WPOS(&write, 48);
	assert_chunk_data(buffer.rchunk, " ab012[", ".......", ".......", ".......", "...----", "-------", "-------", "--     ", NULL);

	destroy_buffer(&buffer);
}

static int test3_init()
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

static int test3_cleanup()
{
	testpool_destroy(pool7);
	testpool_destroy(pool4);
	return CUE_SUCCESS;
}

static void test3_begin()
{
	s2p_buffer_t buffer;
	s2p_read_t read;

	/* null buffer */
	make_buffer(&buffer, pool7, 0, "", true);
	CU_ASSERT_EQUAL(s2p_read_begin(&read, &buffer), 0);
	CU_ASSERT_EQUAL(read.size, 0);
	CU_ASSERT_EQUAL(read.pos, 0);
	destroy_buffer(&buffer);

	/* empty buffer */
	make_buffer(&buffer, pool7, 0, "", false);
	CU_ASSERT_EQUAL(s2p_read_begin(&read, &buffer), 0);
	CU_ASSERT_EQUAL(read.size, 0);
	CU_ASSERT_EQUAL(read.pos, 0);
	destroy_buffer(&buffer);

	/* single-chunk buffer */
	make_buffer(&buffer, pool7, 1, "ABC", false);
	CU_ASSERT_EQUAL(s2p_read_begin(&read, &buffer), 0);
	CU_ASSERT_EQUAL(read.size, 3);
	CU_ASSERT_EQUAL(read.pos, 0);
	destroy_buffer(&buffer);

	/* multi-chunk buffer */
	make_buffer(&buffer, pool7, 1, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", false);
	CU_ASSERT_EQUAL(s2p_read_begin(&read, &buffer), 0);
	CU_ASSERT_EQUAL(read.size, 26);
	CU_ASSERT_EQUAL(read.pos, 0);
	destroy_buffer(&buffer);
}

#define ASSERT_RPOS(SELF, POS) \
	do {\
		size_t n = POS; \
		s2p_chunk_t *chunk = (SELF)->buffer->rchunk; \
		size_t off = (SELF)->buffer->roff; \
		CU_ASSERT_EQUAL(POS, (SELF)->pos); \
		CU_ASSERT((SELF)->pos <= (SELF)->size); \
		while(n) { \
			size_t cur = S2P_MIN(n, chunk->owner->size - off); \
			n -= cur; \
			off += cur; \
			if(off == chunk->owner->size) { \
				chunk = chunk->next; \
				off = 0; \
			} \
		} \
		CU_ASSERT_PTR_EQUAL((SELF)->chunk, chunk); \
		CU_ASSERT_EQUAL((SELF)->off, off); \
		s2p_read_update((SELF)); \
		if((SELF)->size - (SELF)->pos > 0) { \
			CU_ASSERT_EQUAL((SELF)->n, S2P_MIN((SELF)->size - (SELF)->pos, chunk->owner->size - off)); \
			CU_ASSERT_PTR_EQUAL((SELF)->si, chunk->data + off); \
		} \
		else { \
			CU_ASSERT_EQUAL((SELF)->n, 0); \
		} \
	} while(false)

static void test3_seek()
{
	s2p_buffer_t buffer;
	s2p_read_t read;

	make_buffer(&buffer, pool7, 3, "", true);
	s2p_read_begin(&read, &buffer);
	/* case: |---[psu]---| */
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 0, SEEK_SET), 0);
	ASSERT_RPOS(&read, 0);
	/* case: |---[pu]i--| */
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 1, SEEK_SET), -1);
	ASSERT_RPOS(&read, 0);

	destroy_buffer(&buffer);
	
	make_buffer(&buffer, pool7, 3, "A", true);
	s2p_read_begin(&read, &buffer);
	/* case: |---[ps]u--|*/
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 0, SEEK_SET), 0);
	ASSERT_RPOS(&read, 0);
	/* case: |---p[su]--|*/
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 1, SEEK_SET), 0);
	ASSERT_RPOS(&read, 1);
	/* case: |---s[pu]--|*/
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 0, SEEK_SET), 0);
	ASSERT_RPOS(&read, 0);

	destroy_buffer(&buffer);

	make_buffer(&buffer, pool7, 3, "ABCD", true);
	s2p_read_begin(&read, &buffer);
	/* case: |---p..s|u------|*/
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 3, SEEK_SET), 0);
	ASSERT_RPOS(&read, 3);
	/* case: |---...p|[su]------|*/
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 4, SEEK_SET), 0);
	ASSERT_RPOS(&read, 4);
	/* case: |---s...|[pu]------|*/
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 0, SEEK_SET), 0);
	ASSERT_RPOS(&read, 0);

	destroy_buffer(&buffer);

	make_buffer(&buffer, pool7, 3, "ABCDEFGHIJ", true);
	s2p_read_begin(&read, &buffer);
	/* case: |---p...|......u|i */
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 11, SEEK_SET), -1);
	ASSERT_RPOS(&read, 0);
	/* case: |---p...|......[su]|*/
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 10, SEEK_SET), 0);
	ASSERT_RPOS(&read, 10);
	/* case: |---...s|......[pu]|*/
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 3, SEEK_SET), 0);
	ASSERT_RPOS(&read, 3);
	/* case: |---...p|...s..u|*/
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 7, SEEK_SET), 0);
	ASSERT_RPOS(&read, 7);

	destroy_buffer(&buffer);

	make_buffer(&buffer, pool7, 3, "ABCDEFGHIJKLMNOPQ", true);
	s2p_read_begin(&read, &buffer);
	/* case: |---....|...p...|......u|i */
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 18, SEEK_SET), -1);
	ASSERT_RPOS(&read, 0);
	/* case: |---..s.|...p...|......u| */
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 2, SEEK_SET), 0);
	ASSERT_RPOS(&read, 2);
	/* case: |---..p.|.......|..s...u| */
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 13, SEEK_SET), 0);
	ASSERT_RPOS(&read, 13);
	/* case: |---....|...s...|..p...u| */
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 7, SEEK_SET), 0);
	ASSERT_RPOS(&read, 7);
	/* case: |---....|...p...|......[su]| */
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 17, SEEK_SET), 0);
	ASSERT_RPOS(&read, 17);
	/* case: |---..s.|.......|......[pu]| */
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 2, SEEK_SET), 0);
	ASSERT_RPOS(&read, 2);

	CU_ASSERT_EQUAL(s2p_read_seek(&read, 0, SEEK_END), 0);
	ASSERT_RPOS(&read, 17);
	CU_ASSERT_EQUAL(s2p_read_seek(&read, -2, SEEK_END), 0);
	ASSERT_RPOS(&read, 15);
	CU_ASSERT_EQUAL(s2p_read_seek(&read, -4, SEEK_END), 0);
	ASSERT_RPOS(&read, 13);
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 3, SEEK_CUR), 0);
	ASSERT_RPOS(&read, 16);
	CU_ASSERT_EQUAL(s2p_read_seek(&read, -10, SEEK_CUR), 0);
	ASSERT_RPOS(&read, 6);
	CU_ASSERT_EQUAL(s2p_read_seek(&read, -6, SEEK_CUR), 0);
	ASSERT_RPOS(&read, 0);

	s2p_read_seek(&read, 6, SEEK_SET);
	CU_ASSERT_EQUAL(s2p_read_seek(&read, -7, SEEK_CUR), -1);
	ASSERT_RPOS(&read, 6);
	CU_ASSERT_EQUAL(s2p_read_seek(&read, 1, SEEK_END), -1);
	ASSERT_RPOS(&read, 6);

	destroy_buffer(&buffer);
}

static void test3_abort()
{
	s2p_buffer_t buffer;
	s2p_read_t read;
	s2p_chunk_t *chunk;

	make_buffer(&buffer, pool7, 3, "ABCDEFGHIJKLMNOPQ", true);
	chunk = buffer.rchunk;
	s2p_read_begin(&read, &buffer);
	s2p_read_seek(&read, 1, SEEK_SET);
	s2p_read_abort(&read);
	CU_ASSERT_PTR_EQUAL(buffer.rchunk, chunk);
	CU_ASSERT_EQUAL(buffer.roff, 3);
	CU_ASSERT_EQUAL(buffer.fill, 17);

	s2p_read_begin(&read, &buffer);
	s2p_read_seek(&read, 6, SEEK_SET);
	s2p_read_abort(&read);
	CU_ASSERT_PTR_EQUAL(buffer.rchunk, chunk);
	CU_ASSERT_EQUAL(buffer.roff, 3);
	CU_ASSERT_EQUAL(buffer.fill, 17);

	s2p_read_begin(&read, &buffer);
	s2p_read_seek(&read, 0, SEEK_END);
	s2p_read_abort(&read);
	CU_ASSERT_PTR_EQUAL(buffer.rchunk, chunk);
	CU_ASSERT_EQUAL(buffer.roff, 3);
	CU_ASSERT_EQUAL(buffer.fill, 17);

	destroy_buffer(&buffer);
}

static void test3_commit()
{
	s2p_buffer_t buffer;
	s2p_read_t read;
	s2p_chunk_t *chunk;

	/* buffer: |---....|.......|......-| */
	make_buffer(&buffer, pool7, 3, "ABCDEFGHIJKLMNOPQ", true);
	CU_ASSERT_EQUAL(((testpool_t*)pool7)->n_alloc, 3); /* this is just our reference */
	chunk = buffer.rchunk;
	s2p_read_begin(&read, &buffer);
	s2p_read_commit(&read);
	CU_ASSERT_PTR_EQUAL(buffer.rchunk, chunk);
	CU_ASSERT_EQUAL(buffer.roff, 3);
	CU_ASSERT_EQUAL(buffer.fill, 17);
	CU_ASSERT_EQUAL(((testpool_t*)pool7)->n_alloc, 3);

	s2p_read_begin(&read, &buffer);
	s2p_read_seek(&read, 1, SEEK_SET);
	s2p_read_commit(&read);
	CU_ASSERT_PTR_EQUAL(buffer.rchunk, chunk);
	CU_ASSERT_EQUAL(buffer.roff, 4);
	CU_ASSERT_EQUAL(buffer.fill, 16);
	CU_ASSERT_EQUAL(((testpool_t*)pool7)->n_alloc, 3);

	/* buffer: |----...|.......|......-| */

	chunk = chunk->next;
	s2p_read_begin(&read, &buffer);
	s2p_read_seek(&read, 5, SEEK_SET);
	s2p_read_commit(&read);
	CU_ASSERT_PTR_EQUAL(buffer.rchunk, chunk);
	CU_ASSERT_EQUAL(buffer.roff, 2);
	CU_ASSERT_EQUAL(buffer.fill, 11);
	CU_ASSERT_EQUAL(((testpool_t*)pool7)->n_alloc, 2);

	/* buffer: |--.....|......-| */

	chunk = chunk->next;
	s2p_read_begin(&read, &buffer);
	s2p_read_seek(&read, 0, SEEK_END);
	s2p_read_commit(&read);
	CU_ASSERT_PTR_EQUAL(buffer.rchunk, chunk);
	CU_ASSERT_EQUAL(buffer.roff, 6);
	CU_ASSERT_EQUAL(buffer.fill, 0);
	CU_ASSERT_EQUAL(((testpool_t*)pool7)->n_alloc, 1);

	s2p_buffer_destroy(&buffer);
	CU_ASSERT_EQUAL(((testpool_t*)pool7)->n_alloc, 0);
}

static void test3_data()
{
	s2p_buffer_t buffer;
	s2p_read_t read;
	unsigned char tmp[27];
	const char *data = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	/* buffer: |---ABCD|EFGHIJK|LMNOPQR|STUVWXY|Z------| */
	make_buffer(&buffer, pool7, 3, data, true);
	s2p_read_begin(&read, &buffer);
	s2p_read_data(&read, tmp, 1);
	CU_ASSERT_EQUAL(memcmp(tmp, data + 0, 1), 0);
	CU_ASSERT_EQUAL(read.error, 0);
	ASSERT_RPOS(&read, 1);

	s2p_read_data(&read, tmp, 7);
	CU_ASSERT_EQUAL(memcmp(tmp, data + 1, 7), 0);
	CU_ASSERT_EQUAL(read.error, 0);
	ASSERT_RPOS(&read, 8);

	s2p_read_data(&read, tmp, 18);
	CU_ASSERT_EQUAL(memcmp(tmp, data + 8, 18), 0);
	CU_ASSERT_EQUAL(read.error, 0);
	ASSERT_RPOS(&read, 26);
	CU_ASSERT_EQUAL(s2p_read_done(&read), 0);

	s2p_read_data(&read, tmp, 1);
	CU_ASSERT_EQUAL(read.error, EOVERFLOW);
	ASSERT_RPOS(&read, 26);
	CU_ASSERT_EQUAL(s2p_read_done(&read), -1);
	CU_ASSERT_EQUAL(read.error, 0);

	s2p_read_seek(&read, 1, SEEK_SET);
	CU_ASSERT_EQUAL(s2p_read_u8(&read), 0x42);
	CU_ASSERT_EQUAL(s2p_read_u16(&read), 0x4344);
	CU_ASSERT_EQUAL(s2p_read_u32(&read), 0x45464748);
	CU_ASSERT_EQUAL(s2p_read_u64(&read), 0x494a4b4c4d4e4f50);

	destroy_buffer(&buffer);

	make_buffer(&buffer, pool7, 3, "", true);
	s2p_read_begin(&read, &buffer);
	s2p_read_data(&read, tmp, 0);
	CU_ASSERT_EQUAL(read.error, 0);
	ASSERT_RPOS(&read, 0);

	s2p_read_data(&read, tmp, 1);
	CU_ASSERT_EQUAL(read.error, EOVERFLOW);
	ASSERT_RPOS(&read, 0);

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
		ADD_TEST("s2p_write_set + s2p_write_data + s2p_write_done", test2_data);
	END_SUITE;
	BEGIN_SUITE("Buffer read", test3_init, test3_cleanup);
		ADD_TEST("s2p_read_begin", test3_begin);
		ADD_TEST("s2p_read_seek + implicit s2p_read_update", test3_seek);
		ADD_TEST("s2p_read_abort", test3_abort);
		ADD_TEST("s2p_read_commit", test3_commit);
		ADD_TEST("s2p_read_data + s2p_read_done", test3_data);
	END_SUITE;

	return CUE_SUCCESS;
}

