package org.hyperic.sigar.ptql;

import org.hyperic.sigar.SigarException;
import org.hyperic.sigar.SigarProxy;

public class PidQuery implements ProcessQuery {
    protected long pid;

    protected PidQuery() { }

    public PidQuery(long pid) {
        this.pid = pid;
    }

    public PidQuery(String pid) {
        this.pid = Long.parseLong(pid);
    }

    public long getPid()
        throws SigarException {

        return this.pid;
    }

    public boolean match(SigarProxy sigar, long pid) 
        throws SigarException {

        return pid == getPid();
    }
}