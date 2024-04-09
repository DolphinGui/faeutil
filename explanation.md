### How libunwind works in depth
*Assumed prerequesite knowledge:* exception tables, table based exception handling basics


Broadly speaking, zero cost exception handling (also table based exception handling) works
by taking advantage of the same mechanism as DWARF to deduce the stack's format based on
the program counter (PC, also IC). This is known as eh_frame segment, but it doesn't
really include the information of the stack. Rather, it contains instructions for a state
machine that specifies register locations and unwinds the stack.

Ok, let's back up here. C++ throws by calling `__cxa_throw_exception`. (`__cxa_allocate_exception` and
whatnot also happens, but is unimportant to our story.) `__cxa_throw_exception` then calls `_Unwind_RaiseException`,
`__cxa_throw exception` is defined in libsupcxx, but `_Unwind_RaiseException` is actually defined in libgcc,
presumably so that c developers can use it to unwind stack for debugging. `_Unwind_RaiseException` is defined
in unwind.inc, and it calls `uw_frame_state_for` to search through the stack frames. `uw_frame_state_for` itself
finds the FDE and CIE in eh_frame, and calls `execute_cfa_program` to execute the state machine defined by
`eh_frame`. The state machine updates `_Unwind_Context` to include the stack pointer and the value of any registers.

Then phase 2 of exception handling starts, which deals with exception handlers (aka catch blocks, noexcept...).
Personality routines are run, which filter exceptions based on type. Then after that, the `_Unwind_Context` is finally
"installed" in `uw_install_context`. `uw_install_context` is actually a macro that calls `uw_install_context_1`, which
actually unwinds and restores registers based on `_Unwind_Context`. Notably, I'm still not sure by the exact mechanism
it restores registers. It looks like the `memcpy` in `uw_install_context_1` are copying data from the "target" frame
data to the "current" frame, but how writing to a normal struct translates to updating registers is beyond me. In any
case, after some extra work, `__builtin_eh_return` is called to decrement the stack pointer and return back to normal
execution.