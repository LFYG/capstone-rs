//! Bindings to the [capstone library][upstream] disassembly framework.
//!
//! This crate is a wrapper around the
//! [Capstone disassembly library](http://www.capstone-engine.org/),
//! a "lightweight multi-platform, multi-architecture disassembly framework."
//!
//! The [`Capstone`](struct.Capstone.html) struct is the main interface to the library.
//!
//! ```rust
//! extern crate capstone;
//! use capstone::*;
//!
//! const CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";
//! fn main() {
//!     match Capstone::new().x86().mode(x86::ArchMode::Mode32).build() {
//!         Ok(cs) => {
//!             match cs.disasm_all(CODE, 0x1000) {
//!                 Ok(insns) => {
//!                     println!("Got {} instructions", insns.len());
//!
//!                     for i in insns.iter() {
//!                         println!("{}", i);
//!                     }
//!                 },
//!                 Err(err) => {
//!                     println!("Error: {}", err)
//!                 }
//!             }
//!         },
//!         Err(err) => {
//!             println!("Error: {}", err)
//!         }
//!     }
//! }
//! ```
//!
//! Produces:
//!
//! ```no_test
//! Got 2 instructions
//! 0x1000: push rbp
//! 0x1001: mov rax, qword ptr [rip + 0x13b8]
//! ```
//!
//! [upstream]: http://capstone-engine.org/
//!

extern crate capstone_sys;
extern crate libc;

mod builders;
mod capstone;
mod constants;
mod instruction;
mod error;

pub use builders::*;
pub use capstone::*;
pub use constants::*;
pub use instruction::*;
pub use error::*;

#[cfg(test)]
mod test {
    use std::collections::HashSet;
    use capstone_sys::cs_group_type;
    use super::*;

    const X86_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";
    const ARM_CODE: &'static [u8] = b"\x55\x48\x8b\x05\xb8\x13\x00\x00";

    // Aliases for group types
    const JUMP: cs_group_type = cs_group_type::CS_GRP_JUMP;
    const CALL: cs_group_type = cs_group_type::CS_GRP_CALL;
    const RET: cs_group_type = cs_group_type::CS_GRP_RET;
    const INT: cs_group_type = cs_group_type::CS_GRP_INT;
    const IRET: cs_group_type = cs_group_type::CS_GRP_IRET;

    #[test]
    fn test_x86_simple() {
        match Capstone::new().x86().mode(x86::ArchMode::Mode64).build() {
            Ok(cs) => match cs.disasm_all(X86_CODE, 0x1000) {
                Ok(insns) => {
                    assert_eq!(insns.len(), 2);
                    let is: Vec<_> = insns.iter().collect();
                    assert_eq!(is[0].mnemonic().unwrap(), "push");
                    assert_eq!(is[1].mnemonic().unwrap(), "mov");

                    assert_eq!(is[0].address(), 0x1000);
                    assert_eq!(is[1].address(), 0x1001);

                    assert_eq!(is[0].bytes(), b"\x55");
                    assert_eq!(is[1].bytes(), b"\x48\x8b\x05\xb8\x13\x00\x00");
                }
                Err(err) => assert!(false, "Couldn't disasm instructions: {}", err),
            },
            Err(e) => {
                assert!(false, "Couldn't create a cs engine: {}", e);
            }
        }
    }

    #[test]
    fn test_arm_simple() {
        match Capstone::new().arm().mode(arm::ArchMode::Arm).build() {
            Ok(cs) => match cs.disasm_all(ARM_CODE, 0x1000) {
                Ok(insns) => {
                    assert_eq!(insns.len(), 2);
                    let is: Vec<_> = insns.iter().collect();
                    assert_eq!(is[0].mnemonic().unwrap(), "streq");
                    assert_eq!(is[1].mnemonic().unwrap(), "strheq");

                    assert_eq!(is[0].address(), 0x1000);
                    assert_eq!(is[1].address(), 0x1004);
                }
                Err(err) => assert!(false, "Couldn't disasm instructions: {}", err),
            },
            Err(e) => {
                assert!(false, "Couldn't create a cs engine: {}", e);
            }
        }
    }

    #[test]
    fn test_arm64_none() {
        let cs = Capstone::new()
            .arm64()
            .mode(arm64::ArchMode::Arm)
            .build()
            .unwrap();
        assert!(cs.disasm_all(ARM_CODE, 0x1000).is_err());
    }

    #[test]
    fn test_x86_names() {
        match Capstone::new().x86().mode(x86::ArchMode::Mode32).build() {
            Ok(cs) => {
                let reg_id = 1;
                match cs.reg_name(reg_id) {
                    Some(reg_name) => assert_eq!(reg_name, "ah"),
                    None => assert!(false, "Couldn't get register name"),
                }

                let insn_id = 1;
                match cs.insn_name(insn_id) {
                    Some(insn_name) => assert_eq!(insn_name, "aaa"),
                    None => assert!(false, "Couldn't get instruction name"),
                }

                assert_eq!(cs.group_name(1), Some(String::from("jump")));

                let reg_id = 6000;
                match cs.reg_name(reg_id) {
                    Some(_) => assert!(false, "invalid register worked"),
                    None => {}
                }

                let insn_id = 6000;
                match cs.insn_name(insn_id) {
                    Some(_) => assert!(false, "invalid instruction worked"),
                    None => {}
                }

                assert_eq!(cs.group_name(6000), None);
            }
            Err(e) => {
                assert!(false, "Couldn't create a cs engine: {}", e);
            }
        }
    }

    #[test]
    fn test_detail_false_fail() {
        let mut cs = Capstone::new()
            .x86()
            .mode(x86::ArchMode::Mode64)
            .build()
            .unwrap();
        cs.set_detail(false).unwrap();
        let insns: Vec<_> = cs.disasm_all(X86_CODE, 0x1000).unwrap().iter().collect();
        assert_eq!(
            cs.insn_belongs_to_group(&insns[0], 0),
            Err(Error::Capstone(CapstoneError::DetailOff))
        );
        assert_eq!(
            cs.insn_belongs_to_group(&insns[1], 0),
            Err(Error::Capstone(CapstoneError::DetailOff))
        );
    }

    #[test]
    fn test_detail_true() {
        let mut cs = Capstone::new()
            .x86()
            .mode(x86::ArchMode::Mode64)
            .build()
            .unwrap();
        cs.set_detail(true).unwrap();
        let insns: Vec<_> = cs.disasm_all(X86_CODE, 0x1000).unwrap().iter().collect();
        let insn_group_ids = [
            cs_group_type::CS_GRP_JUMP,
            cs_group_type::CS_GRP_CALL,
            cs_group_type::CS_GRP_RET,
            cs_group_type::CS_GRP_INT,
            cs_group_type::CS_GRP_IRET,
        ];
        for insn_idx in 0..1 + 1 {
            for insn_group_id in &insn_group_ids {
                assert_eq!(
                    cs.insn_belongs_to_group(&insns[insn_idx], *insn_group_id as u64),
                    Ok(false)
                );
            }
        }
    }

    /// Assert instruction belongs or does not belong to groups, testing both insn_belongs_to_group
    /// and insn_group_ids
    fn test_instruction_helper(
        cs: &Capstone,
        insn: &Insn,
        mnemonic_name: &str,
        bytes: &[u8],
        expected_groups: &[cs_group_type],
    ) {
        // Check mnemonic
        assert_eq!(
            mnemonic_name,
            cs.insn_name(insn.id() as u64)
                .expect("Failed to get instruction name")
        );
        assert_eq!(
            mnemonic_name,
            insn.mnemonic().expect("Failed to get mnemonic")
        );

        // Assert instruction bytes match
        assert_eq!(bytes, insn.bytes());

        // Assert expected instruction groups is a subset of computed groups through ids
        let instruction_group_ids: HashSet<u8> = cs.insn_groups(&insn)
            .expect("failed to get instruction groups")
            .iter()
            .map(|&x| x)
            .collect();
        let expected_groups_ids: HashSet<u8> = expected_groups.iter().map(|&x| x as u8).collect();
        assert!(
            expected_groups_ids.is_subset(&instruction_group_ids),
            "Expected groups {:?} does NOT match computed insn groups {:?} with ",
            expected_groups_ids,
            instruction_group_ids
        );

        // Assert expected instruction groups is a subset of computed groups through enum
        let instruction_groups_set: HashSet<u8> = cs.insn_groups(&insn)
            .expect("failed to get instruction groups")
            .iter()
            .map(|&x| x)
            .collect();
        let expected_groups_set: HashSet<u8> = expected_groups.iter().map(|&x| x as u8).collect();
        assert!(
            expected_groups_set.is_subset(&instruction_groups_set),
            "Expected groups {:?} does NOT match computed insn groups {:?}",
            expected_groups_set,
            instruction_groups_set
        );

        // Create sets of expected groups and unexpected groups
        let instruction_types: HashSet<cs_group_type> = [
            cs_group_type::CS_GRP_JUMP,
            cs_group_type::CS_GRP_CALL,
            cs_group_type::CS_GRP_RET,
            cs_group_type::CS_GRP_INT,
            cs_group_type::CS_GRP_IRET,
        ].iter()
            .cloned()
            .collect();
        let expected_groups_set: HashSet<cs_group_type> =
            expected_groups.iter().map(|&x| x).collect();
        let not_belong_groups = instruction_types.difference(&expected_groups_set);

        // Assert instruction belongs to belong_groups
        for &belong_group in expected_groups {
            assert_eq!(
                Ok(true),
                cs.insn_belongs_to_group(&insn, belong_group as u64),
                "{:?} does NOT BELONG to group {:?}, but the instruction SHOULD",
                insn,
                belong_group
            );
        }

        // Assert instruction does not belong to not_belong_groups
        for &not_belong_group in not_belong_groups {
            assert_eq!(
                Ok(false),
                cs.insn_belongs_to_group(&insn, not_belong_group as u64),
                "{:?} BELONGS to group {:?}, but the instruction SHOULD NOT",
                insn,
                not_belong_group
            );
        }

        // @todo: check read_registers

        // @todo: check write_registers
    }

    fn instructions_match(
        arch: Arch,
        mode: Mode,
        expected_insns: &[(&str, &[u8], &[cs_group_type])],
    ) {
        let insns_buf: Vec<u8> = expected_insns
            .iter()
            .flat_map(|&(_, bytes, _)| bytes)
            .map(|x| *x)
            .collect();
        let mut cs = Capstone::new_raw(arch, mode).unwrap();

        // Details required to get groups information
        cs.set_detail(true).unwrap();

        let insns: Vec<_> = cs.disasm_all(&insns_buf, 0x1000)
            .expect("Failed to disassemble")
            .iter()
            .collect();

        // Check number of instructions
        assert_eq!(insns.len(), expected_insns.len());

        for (insn, &(expected_mnemonic, expected_bytes, expected_groups)) in
            insns.iter().zip(expected_insns)
        {
            test_instruction_helper(
                &cs,
                insn,
                expected_mnemonic,
                expected_bytes,
                expected_groups,
            )
        }
    }

    #[test]
    fn test_instruction_group_ids() {
        let expected_insns: &[(&str, &[u8], &[cs_group_type])] = &[
            ("nop", b"\x90", &[]),
            ("je", b"\x74\x05", &[JUMP]),
            ("call", b"\xe8\x28\x07\x00\x00", &[CALL]),
            ("ret", b"\xc3", &[RET]),
            ("syscall", b"\x0f\x05", &[INT]),
            ("iretd", b"\xcf", &[IRET]),
            ("sub", b"\x48\x83\xec\x08", &[]),
            ("test", b"\x48\x85\xc0", &[]),
            ("mov", b"\x48\x8b\x05\x95\x4a\x4d\x00", &[]),
            ("mov", b"\xb9\x04\x02\x00\x00", &[]),
        ];

        instructions_match(Arch::X86, Mode::Mode64, expected_insns);
    }

    #[test]
    fn test_invalid_mode() {
        if let Err(err) = Capstone::new_raw(Arch::PPC, Mode::Thumb) {
            assert_eq!(err, Error::Capstone(CapstoneError::InvalidMode));
        } else {
            panic!("Should fail to create given modes");
        }
    }

    #[test]
    fn test_capstone_version() {
        let (major, minor) = Capstone::lib_version();
        println!("Capstone lib version: ({}, {})", major, minor);
        assert!(major > 0 && major < 100, "Invalid major version {}", major);
        assert!(minor < 500, "Invalid minor version {}", minor);
    }

    #[test]
    fn test_capstone_supports_arch() {
        let architectures = vec![
            Arch::ARM,
            Arch::ARM64,
            Arch::MIPS,
            Arch::X86,
            Arch::PPC,
            Arch::SPARC,
            Arch::SYSZ,
            Arch::XCORE,
            // Arch::M68K,
        ];

        println!("Supported architectures");
        for arch in architectures {
            let supports_arch = Capstone::supports_arch(arch);
            println!("  {:?}: {}", arch, if supports_arch { "yes" } else { "no" });
        }
    }

    #[test]
    fn test_capstone_is_diet() {
        println!("Capstone is diet: {}", Capstone::is_diet());
    }
}
