#include <xnu/xnu.h>
#include "kpf.h"

bool need_constraints_patch = false;
bool found_amfi_mac_syscall = false;
static uint32_t* amfi_ret;
uint32_t offsetof_p_flags;

bool kpf_amfi_mac_syscall(struct xnu_pf_patch *patch, uint32_t *opcode_stream) {
    if(found_amfi_mac_syscall)
    {
        panic("amfi_mac_syscall found twice!");
    }
    // Our initial masking match is extremely broad and we have two of them so
    // we have to mark both as non-required, which means returning false does
    // nothing. But we panic on failure, so if we survive, we patched successfully.
    found_amfi_mac_syscall = true;

    bool foundit = false;
    uint32_t *rep = opcode_stream;
    for(size_t i = 0; i < 25; ++i)
    {
        uint32_t op = *rep;
        if(op == 0x321c03e2 /* orr w2, wzr, 0x10 */ || op == 0x52800202 /* movz w2, 0x10 */)
        {
            foundit = true;
            puts("KPF: Found AMFI mac_syscall");
            break;
        }
        rep++;
    }
    if(!foundit)
    {
        panic_at(opcode_stream, "Failed to find w2 in mac_syscall");
    }
    uint32_t *copyin = find_next_insn(rep + 1, 2, 0x94000000, 0xfc000000); // bl
    if(!copyin)
    {
        panic_at(rep, "Failed to find copyin in mac_syscall");
    }
    uint32_t *bl = find_next_insn(copyin + 1, 10, 0x94000000, 0xfc000000);
    if(!bl)
    {
        panic_at(copyin, "Failed to find check_dyld_policy_internal in mac_syscall");
    }
    uint32_t *check_dyld_policy_internal = follow_call(bl);
    if(!check_dyld_policy_internal)
    {
        panic_at(bl, "Failed to follow call to check_dyld_policy_internal");
    }
    // Find call to proc_issetuid
    uint32_t *ref = find_next_insn(check_dyld_policy_internal, 10, 0x94000000, 0xfc000000);
    if((ref[1] & 0xff00001f) != 0x34000000)
    {
        panic_at(ref, "CBZ missing after call to proc_issetuid");
    }
    // Save offset of p_flags
    kpf_find_offset_p_flags(follow_call(ref));
    // Follow CBZ
    ref++;
    ref += sxt32(*ref >> 5, 19); // uint32 takes care of << 2
    // Check for new developer_mode_state()
    bool dev_mode = (ref[0] & 0xfc000000) == 0x94000000;
#ifdef DEV_BUILD
    // 16.0 beta and up
    if(dev_mode != (gKernelVersion.darwinMajor >= 22)) panic_at(ref, "Presence of developer_mode_state doesn't match expected Darwin version");
#endif
    if(dev_mode)
    {
        if((ref[1] & 0xff00001f) != 0x34000000)
        {
            panic_at(ref, "CBZ missing after call to developer_mode_state");
        }
        ref[0] = 0x52800020; // mov w0, 1
        ref += 2;
    }
    // This can be either proc_has_get_task_allow() or proc_has_entitlement()
    bool entitlement = (ref[0] & 0x9f00001f) == 0x90000001 && (ref[1] & 0xffc003ff) == 0x91000021;
#ifdef DEV_BUILD
    // iOS 13 and below
    if(entitlement != (gKernelVersion.darwinMajor <= 19)) panic_at(ref, "Call to proc_has_entitlement doesn't match expected Darwin version");
#endif
    if(entitlement) // adrp+add to x1
    {
        // This is proc_has_entitlement(), so make sure it's the right entitlement
        uint64_t page = ((uint64_t)ref & ~0xfffULL) + adrp_off(ref[0]);
        uint32_t off = (ref[1] >> 10) & 0xfff;
        const char *str = (const char*)(page + off);
        if(strcmp(str, "get-task-allow") != 0)
        {
            panic_at(ref, "Wrong entitlement passed to proc_has_entitlement");
        }
        ref += 2;
    }
    // Move from high reg, bl, and either tbz, 0 or cmp, 0
    uint32_t op = ref[2];
    if((ref[0] & 0xfff003ff) != 0xaa1003e0 || (ref[1] & 0xfc000000) != 0x94000000 || ((op & 0xfff8001f) != 0x36000000 && op != 0x7100001f))
    {
        panic_at(check_dyld_policy_internal, "CMP/TBZ missing after call to %s", entitlement ? "proc_has_entitlement" : "proc_has_get_task_allow");
    }
    ref[1] = 0x52800020; // mov w0, 1
    return true;
}

bool kpf_amfi_mac_syscall_low(struct xnu_pf_patch *patch, uint32_t *opcode_stream) {
    // Unlike the other matches, the case we want is *not* the fallthrough one here.
    // So we need to follow the b.eq for 0x5a here.
    return kpf_amfi_mac_syscall(patch, opcode_stream + 3 + sxt32(opcode_stream[3] >> 5, 19)); // uint32 takes care of << 2
}

bool kpf_amfi_execve_tail(struct xnu_pf_patch* patch, uint32_t* opcode_stream) {
    if(amfi_ret)
    {
        panic("kpf_amfi_execve_tail: found twice!");
    }
    amfi_ret = find_next_insn(opcode_stream, 0x80, RET, 0xFFFFFFFF);
    if (!amfi_ret)
    {
        DEVLOG("kpf_amfi_execve_tail: failed to find amfi_ret");
        return false;
    }
    puts("KPF: Found AMFI execve hook");
    return true;
}

bool kpf_amfi_sha1(struct xnu_pf_patch* patch, uint32_t* opcode_stream) {
    uint32_t* cmp = find_next_insn(opcode_stream, 0x10, 0x7100081f, 0xFFFFFFFF); // cmp w0, 2
    if (!cmp) {
        DEVLOG("kpf_amfi_sha1: failed to find cmp");
        return false;
    }
    puts("KPF: Found AMFI hashtype check");
    xnu_pf_disable_patch(patch);
    *cmp = 0x6b00001f; // cmp w0, w0
    return true;
}

void kpf_find_offset_p_flags(uint32_t *proc_issetugid) {
    DEVLOG("Found kpf_find_offset_p_flags 0x%llx", xnu_ptr_to_va(proc_issetugid));
    if (!proc_issetugid) {
        panic("kpf_find_offset_p_flags called with no argument");
    }
    // FIND LDR AND READ OFFSET
    if((*proc_issetugid & 0xffc003c0) != 0xb9400000)
    {
        panic("kpf_find_offset_p_flags failed to find LDR");
    }
    offsetof_p_flags = ((*proc_issetugid>>10)&0xFFF)<<2;
    DEVLOG("Found offsetof_p_flags %x", offsetof_p_flags);
}

void kpf_amfi_kext_patches(xnu_pf_patchset_t* patchset) {
    // this patch helps us find the return of the amfi function so that we can jump into shellcode from there and modify the cs flags
    // to do that we search for the sequence below also as an example from i7 13.3:
    // 0xfffffff005f340cc      00380b91       add x0, x0, 0x2ce
    // 0xfffffff005f340d0      48000014       b 0xfffffff005f341f0
    // 0xfffffff005f340d4      230c0094       bl sym.stub._cs_system_require_lv
    // 0xfffffff005f340d8      e80240b9       ldr w8, [x23]
    // 0xfffffff005f340dc      80000034       cbz w0, 0xfffffff005f340ec
    // 0xfffffff005f340e0      09408452       movz w9, 0x2200
    // 0xfffffff005f340e4      0801092a       orr w8, w8, w9
    //
    // On iOS 15.4, the control flow changed somewhat:
    // 0xfffffff005b76918      3d280094       bl sym.stub._cs_system_require_lv
    // 0xfffffff005b7691c      080340b9       ldr w8, [x24]
    // 0xfffffff005b76920      60000034       cbz w0, 0xfffffff005b7692c
    // 0xfffffff005b76924      09408452       mov w9, 0x2200
    // 0xfffffff005b76928      03000014       b 0xfffffff005b76934
    // 0xfffffff005b7692c      88002037       tbnz w8, 4, 0xfffffff005b7693c
    // 0xfffffff005b76930      09408052       mov w9, 0x200
    // 0xfffffff005b76934      0801092a       orr w8, w8, w9
    //
    // So now all that we look for is:
    // ldr w8, [x{16-31}]
    // cbz w0, {forward}
    // mov w9, 0x2200
    //
    // To find this with r2, run:
    // /x 080240b90000003409408452:1ffeffff1f0080ffffffffff
    uint64_t matches[] = {
        0xb9400208, // ldr w8, [x{16-31}]
        0x34000000, // cbz w0, {forward}
        0x52844009, // movz w9, 0x2200
    };
    uint64_t masks[] = {
        0xfffffe1f,
        0xff80001f,
        0xffffffff,
    };
    xnu_pf_maskmatch(patchset, "amfi_execve_tail", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_amfi_execve_tail);

    // this patch allows us to run binaries with SHA1 signatures
    // this is done by searching for the sequence below and then finding the cmp w0, 2 (hashtype) and turning that into a cmp w0, w0
    // Example from i7 13.3:
    // 0xfffffff005f36b30      2201d036       tbz w2, 0x1a, 0xfffffff005f36b54
    // 0xfffffff005f36b34      f30305aa       mov x19, x5
    // 0xfffffff005f36b38      f40304aa       mov x20, x4
    // 0xfffffff005f36b3c      f50303aa       mov x21, x3
    // 0xfffffff005f36b40      f60300aa       mov x22, x0
    // 0xfffffff005f36b44      e00301aa       mov x0, x1
    // 0xfffffff005f36b48      a1010094       bl sym.stub._csblob_get_hashtype
    // 0xfffffff005f36b4c      1f080071       cmp w0, 2
    // 0xfffffff005f36b50      61000054       b.ne 0xfffffff005f36b5c
    // to find this in r2 run (make sure to check if the address is aligned):
    // /x 0200d036:1f00f8ff
    uint64_t i_matches[] = {
        0x36d00002, // tbz w2, 0x1a, *
    };
    uint64_t i_masks[] = {
        0xfff8001f,
    };
    xnu_pf_maskmatch(patchset, "amfi_sha1",i_matches, i_masks, sizeof(i_matches)/sizeof(uint64_t), true, (void*)kpf_amfi_sha1);

    // this patch will patch out checks for get_task_allow inside of the mac_syscall
    // this is done by searching for the sequence below (both syscall numbers that are handled inside of the function), then following the call and patching out the get_task_allow check
    // this patch also provides the location to identify the offset of proc->p_flags which is used by the setuid shellcode
    // Example from i7 13.3:
    // 0xfffffff005f365a0      3f6c0171       cmp w1, 0x5b <- we first find this sequence
    // 0xfffffff005f365a4      e0020054       b.eq 0xfffffff005f36600
    // 0xfffffff005f365a8      3f680171       cmp w1, 0x5a
    // 0xfffffff005f365ac      41060054       b.ne 0xfffffff005f36674
    // 0xfffffff005f365b0      40e5054f       movi v0.16b, 0xaa
    // 0xfffffff005f365b4      e007803d       str q0, [sp, 0x10]
    // 0xfffffff005f365b8      ff0700f9       str xzr, [sp, 8]
    // 0xfffffff005f365bc      020600b4       cbz x2, 0xfffffff005f3667c
    // 0xfffffff005f365c0      f40300aa       mov x20, x0
    // 0xfffffff005f365c4      e1430091       add x1, sp, 0x10
    // 0xfffffff005f365c8      e00302aa       mov x0, x2
    // 0xfffffff005f365cc      e2031c32       orr w2, wzr, 0x10
    // 0xfffffff005f365d0      cf020094       bl sym.stub._copyin
    // 0xfffffff005f365d4      f30300aa       mov x19, x0
    // 0xfffffff005f365d8      40050035       cbnz w0, 0xfffffff005f36680
    // 0xfffffff005f365dc      e1230091       add x1, sp, 8
    // 0xfffffff005f365e0      e00314aa       mov x0, x20
    // 0xfffffff005f365e4      ed000094       bl 0xfffffff005f36998 <- then nops this and make sure x1 is -1
    // 0xfffffff005f365e8      e10f40f9       ldr x1, [sp, 0x18]  ; [0x18
    // 0xfffffff005f365ec      e0230091       add x0, sp, 8
    // 0xfffffff005f365f0      e2031d32       orr w2, wzr, 8 <- then this
    // 0xfffffff005f365f4      c9020094       bl sym.stub._copyout_1
    // to find this in r2 run:
    // /x 3f6c0171000000543f68017101000054:ffffffff1f0000ffffffffff1f0000ff
    uint64_t ii_matches[] = {
        0x71016c3f, // cmp w1, 0x5b
        0x54000000, // b.eq
        0x7101683f, // cmp w1, 0x5a
        0x54000001, // b.ne
    };
    uint64_t ii_masks[] = {
        0xffffffff,
        0xff00001f,
        0xffffffff,
        0xff00001f,
    };
    xnu_pf_maskmatch(patchset, "amfi_mac_syscall", ii_matches, ii_masks, sizeof(ii_matches)/sizeof(uint64_t), false, (void*)kpf_amfi_mac_syscall);

    // iOS 15 changed to a switch/case:
    //
    // 0xfffffff00830e9cc      ff4303d1       sub sp, sp, 0xd0
    // 0xfffffff00830e9d0      f6570aa9       stp x22, x21, [sp, 0xa0]
    // 0xfffffff00830e9d4      f44f0ba9       stp x20, x19, [sp, 0xb0]
    // 0xfffffff00830e9d8      fd7b0ca9       stp x29, x30, [sp, 0xc0]
    // 0xfffffff00830e9dc      fd030391       add x29, sp, 0xc0
    // 0xfffffff00830e9e0      08a600b0       adrp x8, 0xfffffff0097cf000
    // 0xfffffff00830e9e4      1f2003d5       nop
    // 0xfffffff00830e9e8      083940f9       ldr x8, [x8, 0x70]
    // 0xfffffff00830e9ec      a8831df8       stur x8, [x29, -0x28]
    // 0xfffffff00830e9f0      d3098052       mov w19, 0x4e
    // 0xfffffff00830e9f4      28680151       sub w8, w1, 0x5a
    // 0xfffffff00830e9f8      1f290071       cmp w8, 0xa
    // 0xfffffff00830e9fc      88150054       b.hi 0xfffffff00830ecac
    // 0xfffffff00830ea00      f40302aa       mov x20, x2
    // 0xfffffff00830ea04      f50300aa       mov x21, x0
    // 0xfffffff00830ea08      296afff0       adrp x9, 0xfffffff007055000
    // 0xfffffff00830ea0c      29c13d91       add x9, x9, 0xf70
    // 0xfffffff00830ea10      8a000010       adr x10, 0xfffffff00830ea20
    // 0xfffffff00830ea14      2b696838       ldrb w11, [x9, x8]
    // 0xfffffff00830ea18      4a090b8b       add x10, x10, x11, lsl 2
    // 0xfffffff00830ea1c      40011fd6       br x10
    // 0xfffffff00830ea20      40e5054f       movi v0.16b, 0xaa
    // 0xfffffff00830ea24      e00f803d       str q0, [sp, 0x30]
    // 0xfffffff00830ea28      ff0f00f9       str xzr, [sp, 0x18]
    // 0xfffffff00830ea2c      f41300b4       cbz x20, 0xfffffff00830eca8
    // 0xfffffff00830ea30      e1c30091       add x1, sp, 0x30
    // 0xfffffff00830ea34      e00314aa       mov x0, x20
    // 0xfffffff00830ea38      02028052       mov w2, 0x10
    // 0xfffffff00830ea3c      8e3ee797       bl 0xfffffff007cde474
    // 0xfffffff00830ea40      f30300aa       mov x19, x0
    // 0xfffffff00830ea44      40130035       cbnz w0, 0xfffffff00830ecac
    // 0xfffffff00830ea48      e1630091       add x1, sp, 0x18
    // 0xfffffff00830ea4c      e00315aa       mov x0, x21
    // 0xfffffff00830ea50      7c020094       bl 0xfffffff00830f440
    // 0xfffffff00830ea54      e11f40f9       ldr x1, [sp, 0x38]
    // 0xfffffff00830ea58      e0630091       add x0, sp, 0x18
    // 0xfffffff00830ea5c      02018052       mov w2, 8
    // 0xfffffff00830ea60      50000014       b 0xfffffff00830eba0
    //
    // We find the "sub wN, w1, 0x5a", then the "mov w2, 0x10; bl ..." after that, then the "bl" after that.
    // /x 20680151:e0ffffff
    uint64_t iii_matches[] = {
        0x51016820, // sub wN, w1, 0x5a
    };
    uint64_t iii_masks[] = {
        0xffffffe0,
    };
    xnu_pf_maskmatch(patchset, "amfi_mac_syscall_alt", iii_matches, iii_masks, sizeof(iii_matches)/sizeof(uint64_t), false, (void*)kpf_amfi_mac_syscall);

    // tvOS/audioOS 16 and bridgeOS 7 apparently got some cases removed, so their codegen looks different again.
    //
    // 0xfffffff008b0ad48      3f780171       cmp w1, 0x5e
    // 0xfffffff008b0ad4c      cc030054       b.gt 0xfffffff008b0adc4
    // 0xfffffff008b0ad50      3f680171       cmp w1, 0x5a
    // 0xfffffff008b0ad54      40060054       b.eq 0xfffffff008b0ae1c
    // 0xfffffff008b0ad58      3f6c0171       cmp w1, 0x5b
    // 0xfffffff008b0ad5c      210e0054       b.ne 0xfffffff008b0af20
    //
    // r2:
    // /x 3f7801710c0000543f680171000000543f6c017101000054:ffffffff1f0000ffffffffff1f0000ffffffffff1f0000ff
    uint64_t iiii_matches[] = {
        0x7101783f, // cmp w1, 0x5e
        0x5400000c, // b.gt
        0x7101683f, // cmp w1, 0x5a
        0x54000000, // b.eq
        0x71016c3f, // cmp w1, 0x5b
        0x54000001, // b.ne
    };
    uint64_t iiii_masks[] = {
        0xffffffff,
        0xff00001f,
        0xffffffff,
        0xff00001f,
        0xffffffff,
        0xff00001f,
    };
    xnu_pf_maskmatch(patchset, "amfi_mac_syscall_low", iiii_matches, iiii_masks, sizeof(iiii_matches)/sizeof(uint64_t), false, (void*)kpf_amfi_mac_syscall_low);
}

static bool found_launch_constraints = false;
bool kpf_launch_constraints_callback(struct xnu_pf_patch *patch, uint32_t *opcode_stream)
{
    if(found_launch_constraints)
    {
        panic("Found launch constraints more than once");
    }
    found_launch_constraints = true;

    uint32_t *stp = find_prev_insn(opcode_stream, 0x200, 0xa9007bfd, 0xffc07fff); // stp x29, x30, [sp, ...]
    if(!stp)
    {
        panic_at(opcode_stream, "Launch constraints: failed to find stack frame");
    }

    uint32_t *start = find_prev_insn(stp, 10, 0xa98003e0, 0xffc003e0); // stp xN, xM, [sp, ...]!
    if(!start)
    {
        start = find_prev_insn(stp, 10, 0xd10003ff, 0xffc003ff); // sub sp, sp, ...
        if(!start)
        {
            panic_at(stp, "Launch constraints: failed to find start of function");
        }
    }

    start[0] = 0x52800000; // mov w0, 0
    start[1] = RET;
    return true;
}

void kpf_launch_constraints(xnu_pf_patchset_t *patchset)
{
    // Disable launch constraints
    uint64_t matches[] = {
        0x52806088, // mov w8, 0x304
        0x14000000, // b 0x...
        0x52802088, // mov w8, 0x104
        0x14000000, // b 0x...
        0x52804088, // mov w8, 0x204
    };
    uint64_t masks[] = {
        0xffffffff,
        0xfc000000,
        0xffffffff,
        0xfc000000,
        0xffffffff,
    };
    xnu_pf_maskmatch(patchset, "launch_constraints", matches, masks, sizeof(matches)/sizeof(uint64_t), true, (void*)kpf_launch_constraints_callback);
}

static void kpf_amfi_init(xnu_pf_range_t *cstring) {
    // Do we need launch constraints patch?
    const char constraints_string[] = "mac_proc_check_launch_constraints";
    const char *constraints_string_match = memmem(cstring->cacheable_base, cstring->size, constraints_string, sizeof(constraints_string));

#ifdef DEV_BUILD
    // 16.0 beta 1 onwards
    if((cryptex_string_match != NULL) != (gKernelVersion.darwinMajor >= 22)) panic("Cryptex presence doesn't match expected Darwin version");
    if((constraints_string_match != NULL) != (gKernelVersion.darwinMajor >= 22)) panic("Launch constraints presence doesn't match expected Darwin version");
#endif
    
    need_constraints_patch = true;
    offsetof_p_flags = -1;
}

static void kpf_amfi_finish(struct mach_header_64 *hdr) {
    if (!found_amfi_mac_syscall) panic("no amfi_mac_syscall");
    if (!amfi_ret) panic("no amfi_ret?");
    if (offsetof_p_flags == -1) panic("no p_flags?");
}

static void kpf_amfi_patches(xnu_pf_patchset_t *patchset)
{
    if(need_constraints_patch) // iOS 16+ only
    {
        kpf_launch_constraints(patchset);
    }
    kpf_amfi_kext_patches(patchset);
}

kpf_component_t kpf_amfi =
{
    .init = kpf_amfi_init,
    .finish = kpf_amfi_finish,
    .patches =
    {
        { "com.apple.driver.AppleMobileFileIntegrity", "__TEXT_EXEC", "__text", XNU_PF_ACCESS_32BIT, kpf_amfi_patches },
        {},
    },
};