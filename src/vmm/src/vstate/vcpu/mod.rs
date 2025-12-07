// Copyright 2023 aztecher, or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

pub mod x86_64;

use crate::{
    arch, cpu,
    utils::memory,
    vstate::{memory::GuestMemoryMmap, vcpu::x86_64::KvmVcpuConfigureError, vm::Vm},
};
use kvm_bindings::{kvm_regs, kvm_sregs};
use kvm_ioctls::{Kvm, VcpuExit, VcpuFd};
use std::os::unix::io::AsRawFd;
use std::sync::mpsc::Sender;
use utils::eventfd::EventFd;
use vm_memory::{GuestAddress, MmapRegion};

/// Errors associated with actions on vcpu.
#[derive(Debug, thiserror::Error)]
pub enum VcpuError {
    /// Cannot open the vcpu file descriptor.
    #[error("{0}")]
    VcpuFd(x86_64::KvmVcpuError),
    /// Failed to get vcpu mmap size.
    #[error("Failed to get vcpu mmap size: {0}")]
    VcpuMmapSize(#[source] kvm_ioctls::Error),
    /// Failed to execute mmap.
    #[error("Memory operation error: {0}")]
    VcpuMmapError(#[source] memory::MemoryError),
    /// Failed to set vcpu id.
    #[error("Failed to set vcpu id: {0}")]
    VcpuSetCpuid(#[source] kvm_ioctls::Error),
    /// Failed to get vcpu special registers.
    #[error("Failed to get vcpu special registers: {0}")]
    VcpuGetSregs(kvm_ioctls::Error),
    /// Failed to set vcpu special registers.
    #[error("Failed to set vcpu special registers: {0}")]
    VcpuSetSregs(kvm_ioctls::Error),
    /// Failed to set vcpu general purpose registers.
    #[error("Failed to set vcpu general purpose registers: {0}")]
    VcpuSetRegs(kvm_ioctls::Error),
    /// Failed to trigger the running of the current vcpu.
    #[error("Failed to trigger the running of the current vcpu: {0}")]
    VcpuRun(kvm_ioctls::Error),
    // FaultyKvmExit(String),
    // UnhandleKvmExit(String),
    // MsrsConfiguration(arch::x86_64::MsrError),
    /// Vcpu registers configuration error.
    #[error("Vcpu registers configuration error: {0}")]
    RegsConfiguration(arch::x86_64::regs::RegError),
    // InterruptConfiguration(arch::x86_64::InterruptError),
    /// KvmVcpu configuration error.
    #[error("Kvm vcpu configuration error: {0}")]
    KvmVcpuConfiguration(KvmVcpuConfigureError),
}

/// Error type for [`Vcpu::copy_kvm_vcpu_fd`].
#[cfg(feature = "gdb")]
#[derive(Debug, thiserror::Error)]
#[error("Failed to clone kvm Vcpu fd: {0}")]
pub enum CopyKvmFdError {
    /// Error with libc dup of kvm Vcpu fd
    DupError(#[from] std::io::Error),
    /// Error creating the Vcpu from the duplicated Vcpu fd
    CreateVcpuError(#[from] kvm_ioctls::Error),
}

/// Error type for [`VcpuHandle::send_event`].
#[derive(Debug, derive_more::From, thiserror::Error)]
#[error("Failed to signal vCPU: {0}")]
pub struct VcpuSendEventError(pub vmm_sys_util::errno::Error);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum VcpuEmulation {
    Handled,
    Interrupted,
    Stopped,
}

#[derive(Debug, Eq, PartialEq)]
pub struct VcpuConfig {
    pub vcpu_count: u8,
}

pub struct Vcpu {
    /// Access to kvm-arch specific functionality.
    kvm_vcpu: x86_64::KvmVcpu,

    /// File descriptor for vcpu to trigger exit event on vmm.
    pub exit_evt: EventFd,

    #[cfg(feature = "gdb")]
    pub gdb_event: Option<Sender<(usize, Sender<()>)>>,
}

impl Vcpu {
    pub fn new(index: u8, vm: &Vm, exit_evt: EventFd) -> Result<Self, VcpuError> {
        use x86_64::*;
        let kvm_vcpu = KvmVcpu::new(index, vm).map_err(VcpuError::VcpuFd)?;
        Ok(Vcpu {
            kvm_vcpu,
            exit_evt,
            #[cfg(feature = "gdb")]
            gdb_event: None,
        })
    }

    pub fn configure(
        &mut self,
        guest_memory: &GuestMemoryMmap,
        kernel_start_addr: GuestAddress,
        cpuid: &mut cpu::Cpuid,
        num_cpus: u8,
    ) -> Result<(), VcpuError> {
        self.kvm_vcpu
            .configure(guest_memory, kernel_start_addr, cpuid, num_cpus)
            .map_err(VcpuError::KvmVcpuConfiguration)?;
        Ok(())
    }

    pub fn setup_kvm_run(&self, kvm: &Kvm) -> Result<MmapRegion, VcpuError> {
        /* This function acts bellow operation
         *
         * 1. Get vCPU mmap size info from KVM
         * > ioctl(fd, KVM_GET_VCPU_MMAP_SIZE, NULL)
         *
         * 2. Map kvm_run structure (that is created at KVM_CREATE_VCPU in host kernel)
         *    into VM process memory (host process's virtual memory address)
         *    using mmap
         * > mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, vcpufd, 0)
         *
         * and return the MmapRegion value that wrap libc::mmap result
         */
        let mmap_size = kvm.get_vcpu_mmap_size().map_err(VcpuError::VcpuMmapSize)?;
        let kvm_run = memory::mmap(mmap_size, self.kvm_vcpu.fd.as_raw_fd(), 0)
            .map_err(VcpuError::VcpuMmapError)?;
        Ok(kvm_run)
    }

    pub fn get_sregs(&self) -> Result<kvm_sregs, VcpuError> {
        self.kvm_vcpu
            .fd
            .get_sregs()
            .map_err(VcpuError::VcpuGetSregs)
    }

    pub fn set_sregs(&self, sregs: &kvm_sregs) -> Result<(), VcpuError> {
        self.kvm_vcpu
            .fd
            .set_sregs(sregs)
            .map_err(VcpuError::VcpuSetSregs)
    }

    pub fn set_regs(&self, regs: &kvm_regs) -> Result<(), VcpuError> {
        self.kvm_vcpu
            .fd
            .set_regs(regs)
            .map_err(VcpuError::VcpuSetRegs)
    }

    /// Attaches the fields required for debugging
    #[cfg(feature = "gdb")]
    pub fn attach_debug_info(&mut self, gdb_event: Sender<(usize, Sender<()>)>) {
        self.gdb_event = Some(gdb_event);
    }

    /// Obtains a copy of the VcpuFd
    #[cfg(feature = "gdb")]
    pub fn copy_kvm_vcpu_fd(&self, vm: &Vm) -> Result<VcpuFd, CopyKvmFdError> {
        // SAFETY: We own this fd so it is considered safe to clone
        let r = unsafe { libc::dup(self.kvm_vcpu.fd.as_raw_fd()) };
        if r < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: We assert this is a valid fd by checking the result from the dup
        unsafe { Ok(vm.fd().create_vcpu_from_rawfd(r)?) }
    }

    pub fn run(&mut self) -> Result<VcpuExit, VcpuError> {
        self.kvm_vcpu.fd.run().map_err(VcpuError::VcpuRun)
    }

    pub fn fd(&self) -> &VcpuFd {
        &self.kvm_vcpu.fd
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::vstate::memory;
    use ::utils::eventfd::EventFd;

    #[test]
    fn test_vcpu_configure() {
        {
            let mut vm = Vm::new().unwrap();
            let gm =
                memory::create_guest_memory(&[(None, GuestAddress(0), 0x1000)], false).unwrap();
            vm.memory_init(&gm, false).unwrap();
            vm.setup_irqchip().unwrap();
            let mut vcpu = Vcpu::new(0, &vm, EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap();
            let kvm_cpuid = vm.supported_cpuid().clone();
            let mut cpuid = cpu::Cpuid::try_from(kvm_cpuid).unwrap();
            assert!(vcpu.configure(&gm, GuestAddress(0), &mut cpuid, 1).is_err());
        }

        {
            let mut vm = Vm::new().unwrap();
            let gm =
                memory::create_guest_memory(&[(None, GuestAddress(0), 128 << 20)], false).unwrap();
            vm.memory_init(&gm, false).unwrap();
            vm.setup_irqchip().unwrap();
            let mut vcpu = Vcpu::new(0, &vm, EventFd::new(libc::EFD_NONBLOCK).unwrap()).unwrap();
            let kvm_cpuid = vm.supported_cpuid().clone();
            let mut cpuid = cpu::Cpuid::try_from(kvm_cpuid).unwrap();
            assert!(vcpu.configure(&gm, GuestAddress(0), &mut cpuid, 1).is_ok());
        }
    }
}
