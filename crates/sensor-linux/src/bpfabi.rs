#[repr(C)]
#[derive(Default)]
pub(crate) struct ProgLoadAttr {
    pub(crate) prog_type: u32,
    pub(crate) insn_cnt: u32,
    pub(crate) insns: u64,
    pub(crate) license: u64,
    pub(crate) log_level: u32,
    pub(crate) log_size: u32,
    pub(crate) log_buf: u64,
    pub(crate) kern_version: u32,
    pub(crate) prog_flags: u32,
    pub(crate) prog_name: [u8; 16],
    pub(crate) prog_ifindex: u32,
    pub(crate) expected_attach_type: u32,
    pub(crate) prog_btf_fd: u32,
    pub(crate) func_info_rec_size: u32,
    pub(crate) func_info: u64,
    pub(crate) func_info_cnt: u32,
    pub(crate) line_info_rec_size: u32,
    pub(crate) line_info: u64,
    pub(crate) line_info_cnt: u32,
    pub(crate) attach_btf_id: u32,
    pub(crate) attach_btf_obj_fd: u32,
    pub(crate) core_relo_cnt: u32,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct LinkCreateAttr {
    pub(crate) prog_fd: u32,
    pub(crate) target_fd: u32,
    pub(crate) attach_type: u32,
    pub(crate) flags: u32,
}

const _: () = {
    assert!(core::mem::size_of::<ProgLoadAttr>() == 120);
    assert!(core::mem::offset_of!(ProgLoadAttr, insns) == 8);
    assert!(core::mem::offset_of!(ProgLoadAttr, license) == 16);
    assert!(core::mem::offset_of!(ProgLoadAttr, prog_name) == 48);
    assert!(core::mem::offset_of!(ProgLoadAttr, expected_attach_type) == 68);
    assert!(core::mem::offset_of!(ProgLoadAttr, attach_btf_id) == 108);
    assert!(core::mem::size_of::<LinkCreateAttr>() == 16);
};
