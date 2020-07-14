// Copyright (C) Julia Evans
//
// Implementation of vmmap was taken from
// https://jvns.ca/blog/2018/01/26/mac-memory-maps/

use libproc::libproc::proc_pid::regionfilename;
use mach::{
    kern_return::KERN_SUCCESS,
    mach_types::*,
    message::*,
    port::{mach_port_name_t, mach_port_t},
    task::*,
    task_info::*,
    vm_region::{
        vm_region_basic_info_data_64_t, vm_region_basic_info_data_t, vm_region_info_t,
        VM_REGION_BASIC_INFO,
    },
    vm_types::*,
};
use nix::unistd::Pid;
use std::mem;

#[derive(Debug, Clone)]
pub(crate) struct Region {
    pub size: mach_vm_size_t,
    pub info: vm_region_basic_info_data_t,
    pub address: mach_vm_address_t,
    pub count: mach_msg_type_number_t,
    pub filename: Option<String>,
}

impl Region {
    pub fn end(&self) -> mach_vm_address_t {
        self.address + self.size as mach_vm_address_t
    }

    pub fn is_read(&self) -> bool {
        self.info.protection & mach::vm_prot::VM_PROT_READ != 0
    }
    pub fn is_write(&self) -> bool {
        self.info.protection & mach::vm_prot::VM_PROT_WRITE != 0
    }
    pub fn is_exec(&self) -> bool {
        self.info.protection & mach::vm_prot::VM_PROT_EXECUTE != 0
    }
}

pub(crate) fn macosx_debug_regions(pid: Pid, task: mach_port_name_t) -> Vec<Region> {
    let init_region = mach_vm_region(pid, task, 1).unwrap();
    let mut vec = vec![];
    let mut region = init_region.clone();
    vec.push(init_region);
    loop {
        match mach_vm_region(pid, task, region.end()) {
            Some(r) => {
                vec.push(r.clone());
                region = r;
            }
            _ => return vec,
        }
    }
}

pub(crate) fn get_task_info(task: mach_port_name_t) -> Option<task_dyld_info> {
    const TASK_DYLD_INFO_COUNT: usize =
        mem::size_of::<task_dyld_info>() / mem::size_of::<natural_t>();
    let mut count = TASK_DYLD_INFO_COUNT;
    let mut dyld_info = unsafe { mem::zeroed::<task_dyld_info>() };
    let ret = unsafe {
        task_info(
            task,
            TASK_DYLD_INFO,
            &mut dyld_info as *mut task_dyld_info as task_info_t,
            &mut count as *mut usize as *mut mach_msg_type_number_t,
        )
    };

    if ret != KERN_SUCCESS {
        None
    } else {
        Some(dyld_info)
    }
}

pub(crate) fn mach_vm_region(
    pid: Pid,
    target_task: mach_port_name_t,
    mut address: mach_vm_address_t,
) -> Option<Region> {
    let mut count = mem::size_of::<vm_region_basic_info_data_64_t>() as mach_msg_type_number_t;
    let mut object_name: mach_port_t = 0;
    let mut size = unsafe { mem::zeroed::<mach_vm_size_t>() };
    let mut info = unsafe { mem::zeroed::<vm_region_basic_info_data_t>() };
    let result = unsafe {
        mach::vm::mach_vm_region(
            target_task as vm_task_entry_t,
            &mut address,
            &mut size,
            VM_REGION_BASIC_INFO,
            &mut info as *mut vm_region_basic_info_data_t as vm_region_info_t,
            &mut count,
            &mut object_name,
        )
    };
    if result != KERN_SUCCESS {
        return None;
    }
    let filename = match regionfilename(pid.as_raw(), address) {
        Ok(x) => Some(x),
        _ => None,
    };
    Some(Region {
        size,
        info,
        address,
        count,
        filename,
    })
}
