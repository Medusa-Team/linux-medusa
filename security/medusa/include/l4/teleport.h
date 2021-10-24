/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _MEDUSA_TELEPORT_H
#define _MEDUSA_TELEPORT_H

#include "l4/comm.h"

enum teleport_opcode_enum {
	tp_NOP,		/* do nothing */
	tp_PUT16,	/* put 16-bit constant */
	tp_PUT32,	/* put 32-bit constant */
	tp_PUTPtr,	/* put Pointer value *JK */
	tp_CUTNPASTE,	/* put the memory region */
	tp_PUTATTRS,	/* put attributes */
	tp_PUTKCLASS,	/* put kclass (without attrs) and assign it a number */
	tp_PUTEVTYPE,	/* put evtype (...) ... */

	tp_HALT,	/* end of the routine */
};

enum teleport_cycle_enum {
	tpc_FETCH,	/* instruction fetch (and decode as well) */
	tpc_EXECUTE,	/* instruction execution */
	tpc_HALT,	/* does nothing */
};

struct teleport_insn_s {
	int opcode;
	union {
		struct {
			void *data[2];
		} nop;
		struct {
			u_int16_t what;
		} put16;
		struct {
			u_int32_t what;
		} put32;
		struct {
			MCPptr_t what;
		} putPtr;
		struct {
			unsigned char *from;
			unsigned int count;
		} cutnpaste;
		struct {
			struct medusa_attribute_s *attrlist;
		} putattrs;
		struct {
			struct medusa_kclass_s *kclassdef;
		} putkclass;
		struct {
			struct medusa_evtype_s *evtypedef;
		} putevtype;
	} args;
};

struct teleport_s {
	/* instruction to execute */
	struct teleport_insn_s *ip;
	enum teleport_cycle_enum cycle;

	/* registers of the processor */
	unsigned char *data_to_user;
	size_t remaining;
	union {
		struct {
			int current_attr;
			struct medusa_comm_attribute_s attr;
		} putattrs;
		struct {
			struct medusa_comm_kclass_s cl;
		} putkclass;
		struct {
			struct medusa_comm_evtype_s ev;
		} putevtype;
	} u;
};

extern void teleport_reset(struct teleport_s *teleport,
			   struct teleport_insn_s *addr,
			   ssize_t (*to_user)(void *from, size_t len));
extern ssize_t teleport_cycle(struct teleport_s *teleport,
			      size_t userlimit);
#endif
