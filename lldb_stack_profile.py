#!/usr/bin/python3

# Configuration constants
# `lldb -P`
LLDB_MODULE_PATH = "/Applications/Xcode.app/Contents/SharedFrameworks/LLDB.framework/Resources/Python"
EXECUTABLE_NAME = "target/debug/examples/stack"
FUNCTION_TO_PROFILE = "join_group"

# Put the macOS lldb module on the path
import sys
sys.path.append(LLDB_MODULE_PATH)

import os
import lldb
import re

def log(frame, bsp):
    fn = frame.GetFunctionName()
    file = frame.line_entry.file
    line = frame.line_entry.line
    sp = frame.sp
    print("{}|{}|{}|{:016x}|{}".format(fn, file, line, sp, bsp - sp))


# Instantiate the debugger
debugger = lldb.SBDebugger.Create()
debugger.SetAsync(False)

# Load and run the target executable, stopping at the function to be profiled
target = debugger.CreateTargetWithFileAndArch(EXECUTABLE_NAME, lldb.LLDB_ARCH_DEFAULT)
filename = target.GetExecutable().GetFilename()
target.BreakpointCreateByName(FUNCTION_TO_PROFILE, filename)
process = target.LaunchSimple (None, None, os.getcwd())

# Set breakpoints on every symbol in the main executable
for symbol in target.modules[0]:
    bp = target.BreakpointCreateByName(symbol.GetName(), filename)
    if bp is None:
        raise Exception("Rejected breakpoint on {}", symbol.GetName())

# Get the base stack frame
thread = process.GetThreadAtIndex(0)
frame = thread.GetFrameAtIndex(0)

bsp = frame.sp
log(frame, bsp)

# Stop at every break point = ever method call and check the stack
last_sp = bsp
last_frame_fn = ""
while last_sp <= bsp:
    # process.Continue()
    if re.search(r'dalek', last_frame_fn):
        thread.StepOver()
    else:
        thread.StepInto()

    frame = thread.GetFrameAtIndex(0)
    log(frame, bsp)

    last_sp = frame.sp
    last_frame_fn = frame.GetFunctionName()

process.Kill()

## For defining a new command

# command script import stack_profile.py
# command script add -f stack_profile.trace hello

#def trace(debugger, command, result, internal_dict):
#  print("world!")

