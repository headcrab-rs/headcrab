use nix::{sys::uio, unistd::Pid};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    mem,
};

pub fn read_string(
    pid: Pid,
    base: usize,
    len: usize,
) -> Result<String, Box<dyn std::error::Error>> {
    let mut read_buf = vec![0; len];
    let buf_iov = uio::IoVec::from_mut_slice(&mut read_buf);
    uio::process_vm_readv(pid, &[buf_iov], &[uio::RemoteIoVec { base, len }])?;

    Ok(String::from_utf8(read_buf)?)
}

pub fn read_usize(pid: Pid, base: usize) -> Result<usize, Box<dyn std::error::Error>> {
    let mut read_buf = [0; mem::size_of::<usize>()];
    let buf_iov = uio::IoVec::from_mut_slice(&mut read_buf);

    let remote_iov = uio::RemoteIoVec {
        base,
        len: mem::size_of::<usize>(),
    };

    uio::process_vm_readv(pid, &[buf_iov], &[remote_iov])?;

    Ok(usize::from_ne_bytes(read_buf))
}

pub fn get_addr_range(pid: Pid) -> Result<usize, Box<dyn std::error::Error>> {
    let file = File::open(format!("/proc/{}/maps", pid))?;
    let mut bufread = BufReader::new(file);
    let mut proc_map = String::new();

    bufread.read_line(&mut proc_map)?;

    let proc_data: Vec<_> = proc_map.split(' ').collect();
    let addr_range: Vec<_> = proc_data[0].split('-').collect();

    Ok(usize::from_str_radix(addr_range[0], 16)?)
}

/*
// This works only if we have write permissions for a given address map.
pub fn write() {
    // Rewrite the address
    uio::process_vm_writev(
        child,
        &[uio::IoVec::from_slice(&read_buf[0..8])],
        &[uio::RemoteIoVec {
            base: OLD_MEM,
            len: mem::size_of::<usize>(),
        }],
    )?;
}
*/
