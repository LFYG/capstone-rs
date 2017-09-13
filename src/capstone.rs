use libc;
use std::convert::From;
use std::ffi::CStr;
use std::mem;
use error::*;
use builders::CapstoneBuilder;
use capstone_sys::*;
use constants::{Arch, Endian, ExtraMode, Mode, OptValue, Syntax};
use instruction::{Detail, Insn, Instructions};

/// An instance of the capstone disassembler
#[derive(Debug)]
pub struct Capstone {
    /// Opaque handle to cs_engine
    csh: csh,

    mode: usize,
    endian: usize,
    syntax: usize,
    extra_mode: usize,
    detail_enabled: bool,

    /// We *must* set `mode`, `extra_mode`, and `endian` at once because `capstone`
    /// handles them inside the arch-specific handler. We store the bitwise OR of these flags that
    /// can be passed directly to `cs_option()`.
    raw_mode: usize,

    /// Architecture
    _arch: Arch,
}

/// Defines a setter on `Capstone` that speculatively changes the arch-specific mode (which
/// includes `mode`, `endian`, and `extra_mode`)
macro_rules! define_set_mode {
    (
        $( #[$func_attr:meta] )*
        => $fn_name:ident, $opt_type:ident, $param_name:ident : $param_type:ident ;
        $cs_base_type:ident
    ) => {
        $( #[$func_attr] )*
        pub fn $fn_name(&mut self, $param_name: $param_type) -> CsResult<()> {
            let old_val = self.$param_name;
            self.$param_name = $cs_base_type::from($param_name) as usize;

            let old_raw_mode = self.raw_mode;
            let new_raw_mode = self.update_raw_mode();

            let result = self._set_cs_option(
                cs_opt_type::$opt_type,
                new_raw_mode,
            );

            if result.is_err() {
                // On error, restore old values
                println!("self: {:?}", self);
                self.raw_mode = old_raw_mode;
                self.$param_name = old_val;
            }

            result
        }
    }
}

impl Capstone {
    /// Create a new instance of the decompiler using the builder pattern interface.
    /// This is the recommended interface to `Capstone`.
    ///
    /// ```
    /// use capstone::{Capstone, BuildsCapstone, x86};
    /// let cs = Capstone::new().x86().mode(x86::ArchMode::Mode32).build();
    /// ```
    pub fn new() -> CapstoneBuilder {
        CapstoneBuilder::new()
    }

    /// Create a new instance of the decompiler using the "raw" interface.
    /// The user must ensure that only sensical `Arch`/`Mode` combinations are used.
    ///
    /// ```
    /// use capstone::{Arch, Capstone, Mode};
    /// let cs = Capstone::new_raw(Arch::X86, Mode::Mode64);
    /// assert!(cs.is_ok());
    /// ```
    pub fn new_raw(arch: Arch, mode: Mode) -> CsResult<Capstone> {
        let mut handle = 0;
        let csarch: cs_arch = arch.into();
        let csmode: cs_mode = mode.into();
        let err = unsafe { cs_open(csarch, csmode, &mut handle) };

        if cs_err::CS_ERR_OK == err {
            let syntax = CS_OPT_SYNTAX_DEFAULT as usize;
            let raw_mode = 0usize;
            let endian = 0usize;
            let extra_mode = 0usize;
            let detail_enabled = false;

            let mut cs = Capstone {
                csh: handle,
                syntax,
                endian,
                mode: csmode as usize,
                extra_mode,
                detail_enabled,
                raw_mode,
                _arch: arch,
            };
            cs.update_raw_mode();
            Ok(cs)
        } else {
            Err(err.into())
        }
    }

    /// Disassemble all instructions in buffer
    pub fn disasm_all(&self, code: &[u8], addr: u64) -> CsResult<Instructions> {
        self.disasm(code, addr, 0)
    }

    /// Disassemble `count` instructions in `code`
    pub fn disasm_count(&self, code: &[u8], addr: u64, count: usize) -> CsResult<Instructions> {
        if count == 0 {
            return Err(Error::CustomError("Invalid dissasemble count; must be > 0"));
        }
        self.disasm(code, addr, count)
    }

    /// Disassembles a `&[u8]` full of instructions.
    ///
    /// Pass `count = 0` to disassemble all instructions in the buffer.
    fn disasm(&self, code: &[u8], addr: u64, count: usize) -> CsResult<Instructions> {
        let mut ptr: *mut cs_insn = unsafe { mem::zeroed() };
        let insn_count = unsafe {
            cs_disasm(
                self.csh,
                code.as_ptr(),
                code.len() as usize,
                addr,
                count as usize,
                &mut ptr,
            )
        };
        if insn_count == 0 {
            return self.error_result();
        }
        Ok(unsafe {
            Instructions::from_raw_parts(ptr, insn_count as isize)
        })
    }

    /// Update `raw_mode` with the bitwise OR of `mode`, `extra_mode`, and `endian`.
    ///
    /// Returns the new `raw_mode`.
    fn update_raw_mode(&mut self) -> usize {
        self.raw_mode = self.mode | self.extra_mode | self.endian;
        self.raw_mode
    }

    /// Set extra modes in addition to normal `mode`
    pub fn set_extra_mode<T: Iterator<Item = ExtraMode>>(&mut self, extra_mode: T) -> CsResult<()> {
        let old_val = self.extra_mode;

        // Bitwise OR extra modes
        self.extra_mode = extra_mode.fold(0usize, |acc, x| acc | cs_mode::from(x) as usize);
        let old_mode = self.raw_mode;
        let new_mode = self.update_raw_mode();
        let result = self._set_cs_option(cs_opt_type::CS_OPT_MODE, new_mode);

        if result.is_err() {
            // On error, restore old values
            self.raw_mode = old_mode;
            self.extra_mode = old_val;
        }

        result
    }

    /// Set the assembly syntax (has no effect on some platforms)
    pub fn set_syntax(&mut self, syntax: Syntax) -> CsResult<()> {
        let syntax_usize = cs_opt_value::from(syntax) as usize;
        let result = self._set_cs_option(cs_opt_type::CS_OPT_SYNTAX, syntax_usize);

        if result.is_ok() {
            self.syntax = syntax_usize;
        }

        result
    }

    define_set_mode!(
        /// Set the endianness (has no effect on some platforms)
        => set_endian, CS_OPT_MODE, endian : Endian; cs_mode);
    define_set_mode!(
        /// Sets the engine's disassembly mode.
        /// Be careful, various combinations of modes aren't supported
        /// See the capstone-sys documentation for more information.
        => set_mode, CS_OPT_MODE, mode : Mode; cs_mode);

    /// Returns an `CsResult::Err` based on current errno.
    fn error_result<T>(&self) -> CsResult<T> {
        Err(unsafe { cs_errno(self.csh) }.into())
    }

    /// Sets disassembling options at runtime.
    ///
    /// Acts as a safe wrapper around capstone's `cs_option`.
    fn _set_cs_option(&mut self, option_type: cs_opt_type, option_value: usize) -> CsResult<()> {
        let err = unsafe { cs_option(self.csh, option_type, option_value) };

        if cs_err::CS_ERR_OK == err {
            Ok(())
        } else {
            Err(err.into())
        }
    }

    /// Controls whether to capstone will generate extra details about disassembled instructions.
    ///
    /// Pass `true` to enable detail or `false` to disable detail.
    pub fn set_detail(&mut self, enable_detail: bool) -> CsResult<()> {
        let option_value: usize = OptValue::from(enable_detail).0 as usize;
        let result = self._set_cs_option(cs_opt_type::CS_OPT_DETAIL, option_value);

        // Only update internal state on success
        if result.is_ok() {
            self.detail_enabled = enable_detail;
        }

        result
    }

    // @todo: use a type alias for reg_ids
    /// Converts a register id `reg_id` to a `String` containing the register name.
    pub fn reg_name(&self, reg_id: u64) -> Option<String> {
        let reg_name = unsafe {
            let _reg_name = cs_reg_name(self.csh, reg_id as libc::c_uint);
            if _reg_name.is_null() {
                return None;
            }

            CStr::from_ptr(_reg_name).to_string_lossy().into_owned()
        };

        Some(reg_name)
    }

    /// Converts an instruction id `insn_id` to a `String` containing the instruction name.
    pub fn insn_name(&self, insn_id: u64) -> Option<String> {
        let insn_name = unsafe {
            let _insn_name = cs_insn_name(self.csh, insn_id as libc::c_uint);
            if _insn_name.is_null() {
                return None;
            }
            CStr::from_ptr(_insn_name).to_string_lossy().into_owned()
        };

        Some(insn_name)
    }

    /// Converts a group id `group_id` to a `String` containing the group name.
    pub fn group_name(&self, group_id: u64) -> Option<String> {
        let group_name = unsafe {
            let _group_name = cs_group_name(self.csh, group_id as libc::c_uint);
            if _group_name.is_null() {
                return None;
            }

            CStr::from_ptr(_group_name).to_string_lossy().into_owned()
        };

        Some(group_name)
    }

    /// Returns `Detail` structure for a given instruction
    ///
    /// Requires:
    /// 1. Instruction was created with detail enabled
    /// 2. Skipdata is disabled
    /// 3. Capstone was not compiled in diet mode
    fn insn_detail<'s, 'i: 's>(&'s self, insn: &'i Insn) -> CsResult<Detail<'i>> {
        if !self.detail_enabled {
            Err(Error::Capstone(CapstoneError::DetailOff))
        } else if insn.id() == 0 {
            Err(Error::Capstone(CapstoneError::IrrelevantDataInSkipData))
        } else if Self::is_diet() {
            Err(Error::Capstone(CapstoneError::IrrelevantDataInDiet))
        } else {
            Ok(unsafe { insn.detail() })
        }
    }

    /// Returns whether the instruction `insn` belongs to the group with id `group_id`.
    pub fn insn_belongs_to_group(&self, insn: &Insn, group_id: u64) -> CsResult<bool> {
        self.insn_detail(insn)?;
        Ok(unsafe {
            cs_insn_group(
                self.csh,
                &insn.0 as *const cs_insn,
                group_id as libc::c_uint,
            )
        })
    }


    /// Returns groups ids to which an instruction belongs.
    pub fn insn_groups<'i>(&self, insn: &'i Insn) -> CsResult<&'i [u8]> {
        let detail = self.insn_detail(insn)?;
        let group_ids: &'i [libc::uint8_t] = unsafe { mem::transmute(detail.groups()) };
        Ok(group_ids)
    }

    /// Checks if an instruction implicitly reads a register with id `reg_id`.
    pub fn register_id_is_read(&self, insn: &Insn, reg_id: u64) -> CsResult<bool> {
        self.insn_detail(insn)?;
        Ok(unsafe {
            cs_reg_read(self.csh, &insn.0 as *const cs_insn, reg_id as libc::c_uint)
        })
    }

    /// Returns list of ids of registers that are implicitly read by instruction `insn`.
    pub fn read_registers<'i>(&self, insn: &'i Insn) -> CsResult<&'i [u8]> {
        let detail = self.insn_detail(insn)?;
        let reg_read_ids: &'i [libc::uint8_t] = unsafe { mem::transmute(detail.regs_read()) };
        Ok(reg_read_ids)
    }

    /// Checks if an instruction implicitly writes to a register with id `reg_id`.
    pub fn register_is_written(&self, insn: &Insn, reg_id: u64) -> CsResult<bool> {
        self.insn_detail(insn)?;
        Ok(unsafe {
            cs_reg_write(self.csh, &insn.0 as *const cs_insn, reg_id as libc::c_uint)
        })
    }

    /// Returns a list of ids of registers that are implicitly written to by the instruction `insn`.
    pub fn write_registers<'i>(&self, insn: &'i Insn) -> CsResult<&'i [u8]> {
        let detail = self.insn_detail(insn)?;
        let reg_write_ids: &'i [libc::uint8_t] = unsafe { mem::transmute(detail.regs_write()) };
        Ok(reg_write_ids)
    }

    /// Returns a tuple (major, minor) indicating the version of the capstone C library.
    pub fn lib_version() -> (u32, u32) {
        let mut major: libc::c_int = 0;
        let mut minor: libc::c_int = 0;
        let major_ptr: *mut libc::c_int = &mut major;
        let minor_ptr: *mut libc::c_int = &mut minor;

        // We can ignore the "hexical" version returned by capstone because we already have the
        // major and minor versions
        let _ = unsafe { cs_version(major_ptr, minor_ptr) };

        (major as u32, minor as u32)
    }

    /// Returns whether the capstone library supports a given architecture.
    pub fn supports_arch(arch: Arch) -> bool {
        unsafe { cs_support(arch as libc::c_int) }
    }

    /// Returns whether the capstone library was compiled in diet mode.
    pub fn is_diet() -> bool {
        unsafe { cs_support(CS_SUPPORT_DIET as libc::c_int) }
    }
}

impl Drop for Capstone {
    fn drop(&mut self) {
        unsafe { cs_close(&mut self.csh) };
    }
}
