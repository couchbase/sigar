# Sigar and PERF

sigar utilize perf counters from `PerfProc`, `PerfOS` and `PerfDisk`
to get information from the running system. These providers
must be enabled in order for the system to work as expected.

You may verify the status of these providers by using
the command `lodctr`:

    C:\Users\Administrator>lodctr /Q:PerfProc
    Performance Counter ID Queries [PERFLIB]:
        Base Index: 0x00000737 (1847)
        Last Counter Text ID: 0x000022F0 (8944)
        Last Help Text ID: 0x000022F1 (8945)

    [PerfProc] Performance Counters (Disabled)
        DLL Name: %SystemRoot%\System32\perfproc.dll
        Open Procedure: OpenSysProcessObject
        Collect Procedure: CollectSysProcessObjectData
        Close Procedure: CloseSysProcessObject

In this case we see that the `PerfProc` provider is disabled
and we may enable it by running:

    C:\Users\Administrator>lodctr /E:PerfProc

And if we rerun the command:

    C:\Users\Administrator>lodctr /Q:PerfProc
    Performance Counter ID Queries [PERFLIB]:
        Base Index: 0x00000737 (1847)
        Last Counter Text ID: 0x000022F0 (8944)
        Last Help Text ID: 0x000022F1 (8945)

    [PerfProc] Performance Counters (Enabled)
        DLL Name: %SystemRoot%\System32\perfproc.dll
	Open Procedure: OpenSysProcessObject
        Collect Procedure: CollectSysProcessObjectData
        Close Procedure: CloseSysProcessObject

(You should verify all the providers)

It is a good idea to try to rebuild and verify once you've changed
any providers to verify that if someone else tries to rebuild
the database it won't be set back:

    lodctr /R
    lodctr /Q:PerfProc
