/*
 * Copyright (C) 2009 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "parse-events.h"

#ifdef HAVE_UDIS86

#include <udis86.h>

static ud_t ud;

static void init_disassembler(void)
{
	ud_init(&ud);
	ud_set_syntax(&ud, UD_SYN_ATT);
}

static const char *disassemble(unsigned char *insn, int len, uint64_t rip,
			       int cr0_pe, int eflags_vm,
			       int cs_d, int cs_l)
{
	int mode;

	if (!cr0_pe)
		mode = 16;
	else if (eflags_vm)
		mode = 16;
	else if (cs_l)
		mode = 64;
	else if (cs_d)
		mode = 32;
	else
		mode = 16;

	ud_set_pc(&ud, rip);
	ud_set_mode(&ud, mode);
	ud_set_input_buffer(&ud, insn, len);
	ud_disassemble(&ud);
	return ud_insn_asm(&ud);
}

#else

static void init_disassembler(void)
{
}

static const char *disassemble(unsigned char *insn, int len, uint64_t rip,
			       int cr0_pe, int eflags_vm,
			       int cs_d, int cs_l)
{
	static char out[15*3+1];
	int i;

	for (i = 0; i < len; ++i)
		sprintf(out + i * 3, "%02x ", insn[i]);
	out[len*3-1] = '\0';
	return out;
}

#endif


#define VMX_EXIT_REASONS			\
	_ER(EXCEPTION_NMI,	0)		\
	_ER(EXTERNAL_INTERRUPT,	1)		\
	_ER(TRIPLE_FAULT,	2)		\
	_ER(PENDING_INTERRUPT,	7)		\
	_ER(NMI_WINDOW,		8)		\
	_ER(TASK_SWITCH,	9)		\
	_ER(CPUID,		10)		\
	_ER(HLT,		12)		\
	_ER(INVLPG,		14)		\
	_ER(RDPMC,		15)		\
	_ER(RDTSC,		16)		\
	_ER(VMCALL,		18)		\
	_ER(VMCLEAR,		19)		\
	_ER(VMLAUNCH,		20)		\
	_ER(VMPTRLD,		21)		\
	_ER(VMPTRST,		22)		\
	_ER(VMREAD,		23)		\
	_ER(VMRESUME,		24)		\
	_ER(VMWRITE,		25)		\
	_ER(VMOFF,		26)		\
	_ER(VMON,		27)		\
	_ER(CR_ACCESS,		28)		\
	_ER(DR_ACCESS,		29)		\
	_ER(IO_INSTRUCTION,	30)		\
	_ER(MSR_READ,		31)		\
	_ER(MSR_WRITE,		32)		\
	_ER(MWAIT_INSTRUCTION,	36)		\
	_ER(MONITOR_INSTRUCTION,39)		\
	_ER(PAUSE_INSTRUCTION,	40)		\
	_ER(MCE_DURING_VMENTRY,	41)		\
	_ER(TPR_BELOW_THRESHOLD,43)		\
	_ER(APIC_ACCESS,	44)		\
	_ER(EPT_VIOLATION,	48)		\
	_ER(EPT_MISCONFIG,	49)		\
	_ER(WBINVD,		54)

#define _ER(reason, val)	{ #reason, val },
struct str_values {
	const char	*str;
	int		val;
};

static struct str_values vmx_exit_reasons[] = {
	VMX_EXIT_REASONS
	{ NULL, -1}
};

static const char *find_vmx_reason(int val)
{
	int i;

	for (i = 0; vmx_exit_reasons[i].val >= 0; i++)
		if (vmx_exit_reasons[i].val == val)
			break;
	if (vmx_exit_reasons[i].str)
		return vmx_exit_reasons[i].str;
	return "UNKOWN";
}

static int kvm_exit_handler(struct trace_seq *s, struct record *record,
			    struct event_format *event, void *context)
{
	unsigned long long val;

	if (pevent_get_field_val(s, event, "exit_reason", record, &val, 1) < 0)
		return -1;

	trace_seq_printf(s, "reason %s", find_vmx_reason(val));

	pevent_print_num_field(s, " rip %0xlx", event, "guest_rip", record, 1);

	return 0;
}

#define KVM_EMUL_INSN_F_CR0_PE (1 << 0)
#define KVM_EMUL_INSN_F_EFL_VM (1 << 1)
#define KVM_EMUL_INSN_F_CS_D   (1 << 2)
#define KVM_EMUL_INSN_F_CS_L   (1 << 3)

static int kvm_emulate_insn_handler(struct trace_seq *s, struct record *record,
				    struct event_format *event, void *context)
{
	unsigned long long rip, csbase, len, flags, failed;
	int llen;
	uint8_t *insn;
	const char *disasm;

	if (pevent_get_field_val(s, event, "rip", record, &rip, 1) < 0)
		return -1;

	if (pevent_get_field_val(s, event, "csbase", record, &csbase, 1) < 0)
		return -1;

	if (pevent_get_field_val(s, event, "len", record, &len, 1) < 0)
		return -1;

	if (pevent_get_field_val(s, event, "flags", record, &flags, 1) < 0)
		return -1;

	if (pevent_get_field_val(s, event, "failed", record, &failed, 1) < 0)
		return -1;

	insn = pevent_get_field_raw(s, event, "insn", record, &llen, 1);
	if (!insn)
		return -1;

	disasm = disassemble(insn, len, rip,
			     flags & KVM_EMUL_INSN_F_CR0_PE,
			     flags & KVM_EMUL_INSN_F_EFL_VM,
			     flags & KVM_EMUL_INSN_F_CS_D,
			     flags & KVM_EMUL_INSN_F_CS_L);

	trace_seq_printf(s, "%llx:%llx: %s%s", csbase, rip, disasm,
			 failed ? " FAIL" : "");

	pevent_print_num_field(s, " rip %0xlx", event, "guest_rip", record, 1);

	return 0;
}


static int kvm_nested_vmexit_inject_handler(struct trace_seq *s, struct record *record,
					    struct event_format *event, void *context)
{
	unsigned long long val;

	pevent_print_num_field(s, " rip %0x016llx", event, "rip", record, 1);

	if (pevent_get_field_val(s, event, "exit_code", record, &val, 1) < 0)
		return -1;

	trace_seq_printf(s, "reason %s", find_vmx_reason(val));

	pevent_print_num_field(s, " ext_inf1: %0x016llx", event, "exit_info1", record, 1);
	pevent_print_num_field(s, " ext_inf2: %0x016llx", event, "exit_info2", record, 1);
	pevent_print_num_field(s, " ext_int: %0x016llx", event, "exit_int_info", record, 1);
	pevent_print_num_field(s, " ext_int_err: %0x016llx", event, "exit_int_info_err", record, 1);

	return 0;
}

static int kvm_nested_vmexit_handler(struct trace_seq *s, struct record *record,
				     struct event_format *event, void *context)
{
	pevent_print_num_field(s, " rip %0x016llx", event, "rip", record, 1);

	return kvm_nested_vmexit_inject_handler(s, record, event, context);
}

union kvm_mmu_page_role {
	unsigned word;
	struct {
		unsigned glevels:4;
		unsigned level:4;
		unsigned quadrant:2;
		unsigned pad_for_nice_hex_output:6;
		unsigned direct:1;
		unsigned access:3;
		unsigned invalid:1;
		unsigned cr4_pge:1;
		unsigned nxe:1;
	};
};

static int kvm_mmu_print_role(struct trace_seq *s, struct record *record,
			      struct event_format *event, void *context)
{
	unsigned long long val;
	static const char *access_str[] =
		{ "---", "--x", "w--", "w-x", "-u-", "-ux", "wu-", "wux" };
	union kvm_mmu_page_role role;

	if (pevent_get_field_val(s, event, "role", record, &val, 1) < 0)
		return -1;

	role.word = (int)val;

	/*
	 * We can only use the structure if file is of the same
	 * endianess.
	 */
	if (pevent_is_file_bigendian(event->pevent) ==
	    pevent_is_host_bigendian(event->pevent)) {

		trace_seq_printf(s, "%u/%u q%u%s %s%s %spge %snxe",
				 role.level,
				 role.glevels,
				 role.quadrant,
				 role.direct ? " direct" : "",
				 access_str[role.access],
				 role.invalid ? " invalid" : "",
				 role.cr4_pge ? "" : "!",
				 role.nxe ? "" : "!");
	} else
		trace_seq_printf(s, "WORD: %08x", role.word);

	pevent_print_num_field(s, " root %u",  event,
			       "root_count", record, 1);

	if (pevent_get_field_val(s, event, "unsync", record, &val, 1) < 0)
		return -1;

	trace_seq_printf(s, "%s%c",  val ? "unsync" : "sync", 0);

	return 0;
}
static int kvm_mmu_get_page_handler(struct trace_seq *s, struct record *record,
				    struct event_format *event, void *context)
{
	unsigned long long val;

	if (pevent_get_field_val(s, event, "gfn", record, &val, 1) < 0)
		return -1;

	trace_seq_printf(s, "sp gfn %llx ", val);

	return kvm_mmu_print_role(s, record, event, context);
}

int PEVENT_PLUGIN_LOADER(struct pevent *pevent)
{
	init_disassembler();

	pevent_register_event_handler(pevent, -1, "kvm", "kvm_exit",
				      kvm_exit_handler, NULL);

	pevent_register_event_handler(pevent, -1, "kvm", "kvm_emulate_insn",
				      kvm_emulate_insn_handler, NULL);

	pevent_register_event_handler(pevent, -1, "kvm", "kvm_nested_vmexit",
				      kvm_nested_vmexit_handler, NULL);

	pevent_register_event_handler(pevent, -1, "kvm", "kvm_nested_vmexit_inject",
				      kvm_nested_vmexit_inject_handler, NULL);

	pevent_register_event_handler(pevent, -1, "kvmmmu", "kvm_mmu_get_page",
				      kvm_mmu_get_page_handler, NULL);

	pevent_register_event_handler(pevent, -1, "kvmmmu", "kvm_mmu_sync_page",
				      kvm_mmu_print_role, NULL);

	pevent_register_event_handler(pevent, -1, "kvmmmu", "kvm_mmu_unsync_page",
				      kvm_mmu_print_role, NULL);

	pevent_register_event_handler(pevent, -1, "kvmmmu", "kvm_mmu_zap_page",
				      kvm_mmu_print_role, NULL);

	return 0;
}
