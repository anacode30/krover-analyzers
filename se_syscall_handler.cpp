/*
ANALYSIS SCENARIO : Symbolic execution of the syscall handler of "setpriority"

-Upon the capturing of the target thread, 
    an int3 breakpoint is installed at the beginning of the syscall handler
    then it is dispatched for native execution
-Once the int3 breakpoint is triggered
    The address storing the first syscall argument is obtained
    A symbolic memory is defined, symbolizing the first syscall argument
    The target is dispatched for symbolic execution
-The execution is terminated oce the execution reaches the end of the syscall handler
    execution terminatoin configs
    Default : executes untill the end of the duspatched function
    In this scenario, execution is continued until the end of the syscall handler

    Additional conditions
    -Event beased termination
    -Instruction count based termination
    -and so on
	
Following APIs privided by KRover are used by the analyst

--Obtain runtime CPU state through VM state
	struct pt_regs <<= m_vm->getPTRegs();
	struct pt_regs in KRover has the same definition as that of the Linux kernel
	
--Declare new memory symbols
	declareSymbolicObject(address, size, isSigned, hasSeed, seed_value, symbol_name)

--Dispatch for symbolic execution
	m_FattCtrl->processFunc(starting_instruction_address)
	
*/

unsigned long setpriority_syscall_handler_adr = kernel_symbol_lookup("__x64_sys_setpriority");

void onTargetThreadCapture(){
    installInt3Breakpoint(setpriority_syscall_handler_adr);
    dispathToNative();
}

void int3BreakpointHandler(){
    beginAnalystMode();
}

bool beginAnalystMode(){
    struct pt_regs      *m_regs;
    unsigned long       pt_regs_adr
    unsigned long       rdi_val;
    string              symbol_name;

    m_regs      = m_VM->getPTRegs();

    /*
    A pt_regs object is passed to the syscall handler as its first argument
    obtain the base address of pt_regs object passed to syscall handler
    */
    /*Introspection : Find the kernel memory storing the syscall arguments*/
    pt_regs_adr = m_regs->regs.rdi;
    rdi_val     = pt_regs_adr + 0x70; /*get the addresss of the first syscall argument, pt_regs base + 0x70*/

    symbol_name = "syscall_arg_0_which";
    declareSymbolicObject(tmp, 8, 1, 1, 0x0, "symbol_name");  

    /*dispatch for symbolic execution, fat control*/
    return m_FattCtrl->processFunc(m_regs->rip);
}