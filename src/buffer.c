#include "lib.h"

void s2p_chunk_ref(
		s2p_chunk_t *chunk)
{
	if(chunk)
		S2P_REF(chunk->refcnt);
}

void s2p_chunk_unref(
		s2p_chunk_t *chunk)
{
	if(chunk && !S2P_UNREF(chunk->refcnt))
		chunk->owner->release(chunk);
}

void s2p_pool_destroy(
		s2p_pool_t *pool)
{
	free(pool);
}

static s2p_chunk_t *malloc_acquire(
		s2p_pool_t *self)

{
	s2p_chunk_t *chunk = malloc(sizeof(s2p_chunk_t) + self->size);
	if(!chunk)
		goto error_1;
	chunk->owner = self;
	chunk->next = NULL;
	chunk->refcnt = 1;
	return chunk;

error_1:
	return NULL;
}

static void malloc_release(
		s2p_chunk_t *chunk)
{
	free(chunk);
}

s2p_pool_t *s2p_pool_malloc_new(
		size_t size)
{
	s2p_pool_t *self = calloc(1, sizeof(s2p_pool_t));
	if(!self)
		goto error_1;
	self->acquire = malloc_acquire;
	self->release = malloc_release;
	self->size = size;
	return self;

error_1:
	return NULL;
}

void s2p_buffer_init(
		s2p_buffer_t *self)
{
	memset(self, 0, sizeof(s2p_buffer_t));
}

void s2p_buffer_destroy(
		s2p_buffer_t *self)
{
	size_t fill = __atomic_load_n(&self->fill, __ATOMIC_SEQ_CST);
	size_t roff = self->roff;
	s2p_chunk_t *cur = self->rchunk;
	if(!cur)
		return;
	else if(!fill) /* buffer is empty (i.e. not null), so we have a ref'ed chunk but no fill */
		s2p_chunk_unref(cur);
	else if(!self->woff) /* buffer is not empty and the write chunk is currently at offset 0, which means that it will never be treated by the following while loop. */
		s2p_chunk_unref(self->wchunk);
	while(fill) {
		s2p_chunk_t *prev = cur;
		size_t n = S2P_MIN(fill, cur->owner->size - roff);
		fill -= n;
		roff = 0;
		cur = cur->next;
		s2p_chunk_unref(prev);
	}
}

/*void s2p_buffer_cpy(
		s2p_buffer_t *self,
		const s2p_buffer_t *other)
{
	s2p_chunk_t *chunk;
	size_t off;
	size_t n;
	size_t total;

	memset(self, 0, sizeof(s2p_buffer_t));
	if(!other || s2p_buffer_status(other) == S2P_BUFFER_NULL)
		return;
	total = __atomic_load_n(&other->fill, __ATOMIC_SEQ_CST);
	chunk = other->rchunk;
	off = other->roff;
	n = total;
	self->rchunk = chunk;
	self->roff = off;
	while(n) {
		size_t cur = S2P_MIN(n, chunk->owner->size - off);
		s2p_chunk_ref(chunk);
		off = 0;
		n -= cur;
		chunk = chunk->next;
	}
	__atomic_store_n(&self->fill, total, __ATOMIC_SEQ_CST);
}*/

void s2p_buffer_cpy(
		s2p_buffer_t *self,
		const s2p_buffer_t *other,
		ssize_t bytes)
{
	s2p_chunk_t *chunk;
	size_t off;
	size_t n;
	size_t total;

	memset(self, 0, sizeof(s2p_buffer_t));
	if(!other || s2p_buffer_status(other) == S2P_BUFFER_NULL)
		return;
	total = __atomic_load_n(&other->fill, __ATOMIC_ACQUIRE);
	if(bytes >= 0)
		total = S2P_MIN(total, (size_t)bytes);
	n = total;
	chunk = other->rchunk;
	off = other->roff;
	self->rchunk = chunk;
	self->roff = off;
	while(n) {
		size_t cur = S2P_MIN(n, chunk->owner->size - off);
		s2p_chunk_ref(chunk);
		off = 0;
		n -= cur;
		chunk = chunk->next;
	}
	__atomic_store_n(&self->fill, total, __ATOMIC_SEQ_CST);
}

int s2p_buffer_cmp_data(
		const s2p_buffer_t *self,
		const void *data,
		size_t size)
{
	const char *si = data;
	size_t off = self->roff;
	size_t fill = __atomic_load_n(&self->fill, __ATOMIC_SEQ_CST);
	size_t n = S2P_MIN(fill, size);
	s2p_chunk_t *c = self->rchunk;

	while(n) {
		int cmp;
		size_t cur = S2P_MIN(c->owner->size - off, n);
		cmp = memcmp(c->data + off, si, cur);
		if(cmp < 0)
			return -1;
		else if(cmp > 0)
			return 1;
		n -= cur;
		si += cur;
		off = 0;
		c = c->next;
	}
	return 0;
}

int s2p_buffer_cmp(
		const s2p_buffer_t *self,
		const s2p_buffer_t *other,
		ssize_t n)
{
	s2p_chunk_t *ca = self->rchunk;
	s2p_chunk_t *cb = other->rchunk;
	size_t sizea;
	size_t sizeb;
	size_t offa = self->roff;
	size_t offb = other->roff;
	size_t sfill = __atomic_load_n(&self->fill, __ATOMIC_SEQ_CST);
	size_t ofill = __atomic_load_n(&other->fill, __ATOMIC_SEQ_CST);
	size_t total = S2P_MIN(sfill, ofill);
	if(n >= 0)
		total = S2P_MIN(total, (size_t)n);

	if(!total)
		return 0;
	sizea = ca->owner->size;
	sizeb = cb->owner->size;

	for(;;) {
		size_t cura = S2P_MIN(sizea - offa, total);
		size_t curb = S2P_MIN(sizeb - offb, total);
		size_t cur = S2P_MIN(cura, curb);
		int cmp = memcmp(ca->data + offa, cb->data + offb, cur);
		if(cmp < 0)
			return -1;
		else if(cmp > 0)
			return 1;
		total -= cur;
		if(!total) {
			if(sfill > ofill)
				return 1;
			else if(sfill < ofill)
				return -1;
			else
				return 0;
		}
		if(cura < curb) {
			ca = ca->next;
			offa = 0;
			offb += cur;
		}
		else if(cura > curb) {
			cb = cb->next;
			offb = 0;
			offa += cur;
		}
		else {
			ca = ca->next;
			cb = cb->next;
			offa = 0;
			offb = 0;
		}
	}
}

/*void s2p_buffer_clear(
		s2p_buffer_t *self)
{
	size_t fill = __atomic_exchange_n(&self->fill, 0, __ATOMIC_SEQ_CST);
	self->
	while(fill) {
		s2p_chunk_t *chunk = self->rchunk;
		size_t size = S2P_MIN(chunk->owner->size - self->roff, self->fill);
		self->rchunk = chunk->next;
		fill -= size;
		self->roff = 0;
		s2p_chunk_unref(chunk);
	}
	self->rchunk = NULL;
	self->roff = 0;
	self->wchunk = NULL;
	self->woff = 0;
}*/

size_t s2p_buffer_available(
		const s2p_buffer_t *self)
{
	if(self)
		return __atomic_load_n(&self->fill, __ATOMIC_ACQUIRE);
	else
		return 0;
}

int s2p_buffer_status(
		const s2p_buffer_t *self)
{
	if(self) {
		int status = 0;
		if(!self->wchunk) {
			if(self->rchunk)
				status |= S2P_BUFFER_RDONLY;
			else
				return S2P_BUFFER_NULL;
		}
		if(__atomic_load_n(&self->fill, __ATOMIC_SEQ_CST))
			status |= S2P_BUFFER_NOT_EMPTY;
		else
			status |= S2P_BUFFER_EMPTY;
		return status;
	}
	else
		return S2P_BUFFER_INVALID;
}

int s2p_write_begin(
		s2p_write_t *self,
		s2p_buffer_t *buffer,
		s2p_pool_t *pool)
{
	int status = s2p_buffer_status(buffer);

	if(status == S2P_BUFFER_NULL) {
		buffer->rchunk = pool->acquire(pool);
		if(!buffer->rchunk)
			goto error_1;
		buffer->roff = 0;
		buffer->wchunk = buffer->rchunk;
		buffer->woff = 0;
	}
	else if(status & S2P_BUFFER_RDONLY) {
		errno = EACCES;
		goto error_1;
	}

	memset(self, 0, sizeof(s2p_write_t));
	self->buffer = buffer;
	self->pool = pool;
	self->chunk = buffer->wchunk;
	self->off = buffer->woff;
	self->echunk = buffer->wchunk;
	self->eoff = buffer->woff;
	s2p_write_update(self);
	return 0;

error_1:
	return -1;
}

/* seek to offset relative to begin() */
int s2p_write_seek(
		s2p_write_t *self,
		ssize_t rel,
		int whence)
{
	size_t pos;
	switch(whence) {
		case SEEK_SET: pos = rel; break;
		case SEEK_CUR: pos = rel + self->pos; break;
		case SEEK_END: pos = rel + self->size; break;
		default: errno = EINVAL; return -1;
	}
	if(pos > self->size) {
		errno = EOVERFLOW;
		goto error_1;
	}
	else if(self->echunk == self->buffer->wchunk) { /* we currently have just one chunk, so we can finish immediately */
		self->pos = pos;
		self->off = pos + self->buffer->woff;
		s2p_write_update(self);
		return 0;
	}
	else if(pos >= self->size - self->eoff) { /* we can start at beginning of the last chunk */
		self->pos = pos;
		self->off = self->eoff + self->pos - self->size;
		self->chunk = self->echunk;
		s2p_write_update(self);
		return 0;
	}
	else if(self->chunk == self->buffer->wchunk) { /* we are in the beginning chunk, so do start at the very beginning */
		self->pos = 0;
		self->off = self->buffer->woff;
	}
	else if(pos < self->pos - self->off) { /* we must start at the very beginning */
		self->chunk = self->buffer->wchunk;
		self->off = self->buffer->woff;
		self->pos = 0;
	}
	else { /* we can start at current position */
		self->pos -= self->off;
		self->off = 0;
		pos -= self->pos;
	}
	while(pos) {
		size_t cur = S2P_MIN(pos, self->chunk->owner->size - self->off);
		self->pos += cur;
		self->off += cur;
		pos -= cur;
		if(self->off == self->chunk->owner->size) {
			if(!self->chunk->next) {
				self->chunk->next = self->pool->acquire(self->pool);
				if(!self->chunk->next)
					goto error_1;
			}
			self->chunk = self->chunk->next;
			self->off = 0;
		}
	}
	s2p_write_update(self);
	return 0;

error_1:
	return -1;
}

void s2p_write_update(
		s2p_write_t *self)
{
	self->di = self->chunk->data + self->off;
	if(self->chunk == self->echunk)
		self->n = self->eoff - self->off;
	else
		self->n = self->chunk->owner->size - self->off;
}

int s2p_write_reserve(
		s2p_write_t *self,
		size_t size,
		int whence)
{
	size_t pos;
	switch(whence) {
		case SEEK_SET: pos = size; break;
		case SEEK_CUR: pos = size + self->pos; break;
		case SEEK_END: pos = size + self->size; break;
		default: errno = EINVAL; return -1;
	}
	if(pos <= self->size)
		return 0;
	pos -= self->size;
	while(pos) {
		size_t cur = S2P_MIN(pos, self->echunk->owner->size - self->eoff);
		self->size += cur;
		self->eoff += cur;
		pos -= cur;
		if(self->eoff == self->echunk->owner->size) {
			if(!self->echunk->next) {
				self->echunk->next = self->pool->acquire(self->pool);
				if(!self->echunk->next)
					goto error_1;
			}
			self->echunk = self->echunk->next;
			self->eoff = 0;
		}
	}
	s2p_write_update(self);
	return 0;

error_1:
	return -1;
}

void s2p_write_set(
		s2p_write_t *self,
		char c,
		size_t n)
{
	s2p_chunk_t *chunk = self->chunk;
	size_t off = self->off;
	size_t total = n;
	unsigned char *di = chunk->data + off;
	if(self->error || !total)
		return;
	while(n) {
		size_t cur = S2P_MIN(n, chunk->owner->size - off);
		memset(di, c, cur);
		off += cur;
		n -= cur;
		di += cur;
		if(off == chunk->owner->size) {
			if(!chunk->next) {
				chunk->next = self->pool->acquire(self->pool);
				if(!chunk->next) {
					self->error = errno;
					return;
				}
			}
			chunk = chunk->next;
			off = 0;
			di = chunk->data;
		}
	}
	self->chunk = chunk;
	self->off = off;
	self->pos += total;
	if(self->size < self->pos) { /* we wrote beyond current end position */
		self->size = self->pos;
		self->eoff = off;
		self->echunk = chunk;
	}
}

void s2p_write_data(
		s2p_write_t *self,
		const void *src,
		size_t n)
{
	s2p_chunk_t *chunk = self->chunk;
	size_t off = self->off;
	size_t total = n;
	unsigned char *di = chunk->data + off;
	if(self->error || !total)
		return;
	while(n) {
		size_t cur = S2P_MIN(n, chunk->owner->size - off);
		memcpy(di, src, cur);
		src += cur;
		off += cur;
		n -= cur;
		di += cur;
		if(off == chunk->owner->size) {
			if(!chunk->next) {
				chunk->next = self->pool->acquire(self->pool);
				if(!chunk->next) {
					self->error = errno;
					return;
				}
			}
			chunk = chunk->next;
			off = 0;
			di = chunk->data;
		}
	}
	self->chunk = chunk;
	self->off = off;
	self->pos += total;
	if(self->size < self->pos) { /* we wrote beyond current end position */
		self->size = self->pos;
		self->eoff = off;
		self->echunk = chunk;
	}
}

void s2p_write_str(
		s2p_write_t *self,
		const char *string)
{
	if(!string)
		return;
	s2p_write_data(self, string, strlen(string));
}

void s2p_write_strn(
		s2p_write_t *self,
		const char *string,
		ssize_t n)
{
	if(!string)
		return;
	else if(n < 0)
		n = strlen(string);
	else
		n = strnlen(string, n);
	s2p_write_data(self, string, n);
}

void s2p_write_u8(
		s2p_write_t *self,
		uint8_t v)
{
	s2p_write_data(self, &v, 1);
}

void s2p_write_u16(
		s2p_write_t *self,
		uint16_t v)
{
	v = htobe16(v);
	s2p_write_data(self, &v, 2);
}

void s2p_write_u32(
		s2p_write_t *self,
		uint32_t v)
{
	v = htobe32(v);
	s2p_write_data(self, &v, 4);
}

void s2p_write_u64(
		s2p_write_t *self,
		uint64_t v)
{
	v = htobe64(v);
	s2p_write_data(self, &v, 8);
}

int s2p_write_done(
		s2p_write_t *self)
{
	int error = self->error;
	self->error = 0;
	s2p_write_update(self);

	if(error) {
		errno = error;
		return -1;
	}
	else
		return 0;
}

void s2p_write_abort(
		s2p_write_t *self)
{
	s2p_chunk_t *cur = self->buffer->wchunk->next;
	while(cur) {
		s2p_chunk_t *prev = cur;
		cur = cur->next;
		s2p_chunk_unref(prev);
	}
}

int s2p_write_commit(
		s2p_write_t *self)
{
	if(self->error) {
		errno = self->error;
		return -1;
	}
	self->buffer->wchunk = self->echunk;
	self->buffer->woff = self->eoff;
	__atomic_fetch_add(&self->buffer->fill, self->size, __ATOMIC_SEQ_CST);
	return 0;
}

int s2p_read_begin(
		s2p_read_t *self,
		s2p_buffer_t *buffer)
{
	memset(self, 0, sizeof(s2p_read_t));
	self->buffer = buffer;
	self->size = __atomic_load_n(&buffer->fill, __ATOMIC_SEQ_CST);
	self->chunk = self->buffer->rchunk;
	self->off = self->buffer->roff;
	s2p_read_update(self);

	return 0;
}

void s2p_read_update(
		s2p_read_t *self)
{
	if(self->chunk) {
		self->si = self->chunk->data + self->off;
//		self->n = 
	}
	else {
		self->si = NULL;
		self->n = 0;
	}
}

#ifdef TESTING
#include "test/buffer.h"
#endif

