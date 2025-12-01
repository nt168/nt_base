// #ifndef NT_TYPE_H
// #define NT_TYPE_H

// #include <stdint.h>
// #include <sys/types.h>
// #include <sys/stat.h>
// #include <limits.h>

// #if defined(_WINDOWS)
// #	define NT_THREAD_LOCAL __declspec(thread)
// #else
// #	define NT_THREAD_LOCAL __thread
// #endif

// typedef uint32_t	nt_uint32_t;

// //typedef int	nt_syserror_t;

// #endif	/* _WINDOWS */

// #if defined(_WINDOWS)
// #	define nt_stat(path, buf)		__nt_stat(path, buf)
// #	define nt_fstat(fd, buf)		_fstat64(fd, buf)

// typedef __int64	nt_offset_t;
// #	define nt_lseek(fd, offset, whence)	_lseeki64(fd, (nt_offset_t)(offset), whence)

// #elif defined(__MINGW32__)
// #	define nt_stat(path, buf)		__nt_stat(path, buf)
// #	define nt_fstat(fd, buf)		_fstat64(fd, buf)

// typedef off64_t	nt_offset_t;
// #	define nt_lseek(fd, offset, whence)	lseek64(fd, (nt_offset_t)(offset), whence)

// #else
// #	define nt_stat(path, buf)		stat(path, buf)
// #	define nt_fstat(fd, buf)		fstat(fd, buf)

// typedef off_t	nt_offset_t;
// #	define nt_lseek(fd, offset, whence)	lseek(fd, (nt_offset_t)(offset), whence)

// #endif


// #define NT_SIZE_T_ALIGN8(size)	(((size) + 7) & ~(size_t)7)

// /* macro to test if a signed value has been assigned to unsigned type (char, short, int, long long) */
// #define NT_IS_TOP_BIT_SET(x)	(0 != ((__UINT64_C(1) << ((sizeof(x) << 3) - 1)) & (x)))

// #if defined(_WINDOWS) || defined(__MINGW32__)
// 	#define localtime_r(x, y)	localtime_s(y, x)
// #endif

// typedef struct nt_variant nt_variant_t;

// #endif
