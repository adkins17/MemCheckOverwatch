#ifndef MEMCHECK_RUNTIME_H
#define MEMCHECK_RUNTIME_H

#ifdef __cplusplus
extern "C" {
#endif

void memcheck_dump_reports(void);

/*
 * Force a report dump before process exit. This is useful for long-running
 * server smoke tests that want a mid-run leak snapshot.
 */

#ifdef __cplusplus
}
#endif

#endif
