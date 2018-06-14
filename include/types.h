#pragma once

typedef struct s2p_pool s2p_pool_t;
typedef struct s2p_chunk s2p_chunk_t;
typedef struct s2p_buffer s2p_buffer_t;
typedef struct s2p_write s2p_write_t;
typedef struct s2p_read s2p_read_t;
typedef unsigned int s2p_refcnt_t;

typedef s2p_chunk_t *(*s2p_acquire_t)(s2p_pool_t *self);
typedef void (*s2p_release_t)(s2p_chunk_t *chunk);

struct s2p_pool {
	s2p_acquire_t acquire;
	s2p_release_t release;
	size_t size; /* size of one chunk */
};

struct s2p_chunk {
	s2p_pool_t *owner;
	s2p_chunk_t *next;
	s2p_refcnt_t refcnt;
	unsigned char data[];
};

/* init: bzero memory */
struct s2p_buffer {
	s2p_chunk_t *wchunk; /* wchunk == NULL, rchunk != NULL: read-only */
	s2p_chunk_t *rchunk;
	size_t woff;
	size_t roff;
	size_t fill;
};

/* buffer->wchunk must not be unref'd while a s2p_writer is active on a buffer */
struct s2p_write {
	s2p_pool_t *pool;
	s2p_buffer_t *buffer;
	/* current position */
	s2p_chunk_t *chunk;
	size_t off;
	/* end position */
	s2p_chunk_t *echunk;
	size_t eoff;

	/* total size of current write transaction */
	/* access: public read-only */
	size_t pos; /* offset from buffer->wchunk + buffer->woff */
	size_t size; /* reserved bytes for current write transaction */

	/* access: public read/write */
	unsigned char *di; /* current target pointer */
	size_t n; /* number of bytes that can be written to 'di' */
	int error; /* used only for write_data() and dependent functions */
};

struct s2p_read {
	s2p_buffer_t *buffer;
	s2p_chunk_t *chunk;
	size_t off;

	/* total size of current read transaction */
	/* access: public read-only */
	size_t pos; /* offset from buffer->rchunk + buffer->roff */
	size_t size; /* reserved bytes for current write transaction */

	/* public read/write */
	const unsigned char *si; /* current source pointer*/
	size_t n; /* number of bytes that can be read from 'si' */
	int error; /* used only for read_data() and dependent functions */
};

void s2p_chunk_ref(
		s2p_chunk_t *self);

void s2p_chunk_unref(
		s2p_chunk_t *self);

void s2p_pool_destroy(
		s2p_pool_t *pool);


s2p_pool_t *s2p_pool_malloc_new(
		size_t size);

/* status & FILL_MASK == 0 => status == NULL, i.e. there is no such thing as a read-only null buffer */
enum {
	S2P_BUFFER_NULL,
	S2P_BUFFER_EMPTY = 0x01,
	S2P_BUFFER_NOT_EMPTY = 0x02,
	S2P_BUFFER_INVALID = 0x03,
	S2P_BUFFER_RDONLY = 0x04,

	S2P_BUFFER_FILL_MASK = 0x03
};

/* while a read/write is active, just the const self functions may be used. */
void s2p_buffer_reset(
		s2p_buffer_t *self);

/* make a read-only copy of the buffer; 'self' is expected to be uninitialized
 * there must be no read handler active for 'other' */
void s2p_buffer_cpy(
		s2p_buffer_t *self,
		const s2p_buffer_t *other);

/* make a read-only copy of the buffer; 'self' is expected to be uninitialized */
void s2p_buffer_ncpy(
		s2p_buffer_t *self,
		const s2p_buffer_t *other,
		ssize_t n);

/* compare buffer content with byte array; < 0: buffer < data; > 0: buffer > data; == 0: buffer == data */
int s2p_buffer_cmp_data(
		const s2p_buffer_t *self,
		const void *data,
		size_t size);

int s2p_buffer_cmp(
		const s2p_buffer_t *self,
		const s2p_buffer_t *other);

size_t s2p_buffer_available(
		const s2p_buffer_t *self);

/* returns S2P_BUFFER_x */
int s2p_buffer_status(
		const s2p_buffer_t *self);

int s2p_write_begin(
		s2p_write_t *self,
		s2p_buffer_t *buffer,
		s2p_pool_t *pool);

/* returns current write offset relative to begin() */
size_t s2p_write_tell(
		s2p_write_t *self);

/* seek to offset relative to begin() */
int s2p_write_seek(
		s2p_write_t *self,
		ssize_t off,
		int whence);

/* reserve 'size' from offset relative to 'whence' */
int s2p_write_reserve(
		s2p_write_t *self,
		size_t size,
		int whence);

/* set 'target' and 'remaining' to current position */
void s2p_write_update(
		s2p_write_t *self);

/* advance current pointer by 'n'; cannot advance beyond end
 * NOTE: s2p_write_update() required after following functions have been used! */

int s2p_write_advance(
		s2p_write_t *self,
		size_t n);

/* write_data dependent functions: since they are meant to
 * be called often in succession, the cause the write handler to become dirty.
 * s2p_write_update() must be called to update self->di.
 * it also uses self->error to indicate any error occured during a write sequence.
 * when write sequence is done, caller may use write_done() to clean the handler again
 * and retrieve a possible error. */

void s2p_write_data(
		s2p_write_t *self,
		const void *src,
		size_t n);

void s2p_write_str(
		s2p_write_t *self,
		const char *string);

void s2p_write_strn(
		s2p_write_t *self,
		const char *string,
		ssize_t n);

void s2p_write_u8(
		s2p_write_t *self,
		uint8_t v);

void s2p_write_u16(
		s2p_write_t *self,
		uint16_t v);

void s2p_write_u32(
		s2p_write_t *self,
		uint32_t v);

void s2p_write_u64(
		s2p_write_t *self,
		uint64_t v);

/* after using write_data() dependen functions, the buffer is a bit dirty.
 * calling this function cleans the buffer (calls write_update(), clears error)
 * if self->error is set, the value is copied into errno and -1 is returned */
int s2p_write_done(
		s2p_write_t *self);

/* note: 'self' becomes uninitialized after abort() or commit() */
void s2p_write_abort(
		s2p_write_t *self);

int s2p_write_commit(
		s2p_write_t *self);

int s2p_read_begin(
		s2p_read_t *self,
		s2p_buffer_t *buffer);

void s2p_read_update(
		s2p_read_t *self);

/*int s2p_read_take(
		s2p_read_t *self);
*/
