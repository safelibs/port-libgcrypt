# Rendered from the upstream tests/*.in substitutions used by the phase-1
# direct-compile harness.
EXEEXT=
RUN_LARGE_DATA_TESTS=yes
TESTS_ENVIRONMENT=GCRYPT_IN_REGRESSION_TEST=1
COMPAT_LINUX_SOURCES=compat.c
LDADD_FOR_TESTS_KLUDGE=-Wl,--disable-new-dtags
