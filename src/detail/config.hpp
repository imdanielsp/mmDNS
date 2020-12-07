

#ifndef MMDNS_INLINE
#if defined(__has_cpp_attribute)
#if __has_cpp_attribute(gnu::always_inline)
#define MMDNS_INLINE [[gnu::always_inline]]
#endif
#endif

#ifndef MMDNS_INLINE
#define MMDNS_INLINE inline
#endif
#endif

#ifndef MMDNS_NON_NULL
#if defined(__has_cpp_attribute)
#if __has_cpp_attribute(_Nonnull)
#define MMDNS_NON_NULL _Nonnull
#endif
#endif

#ifndef MMDNS_NON_NULL
#define MMDNS_NON_NULL
#endif

#endif