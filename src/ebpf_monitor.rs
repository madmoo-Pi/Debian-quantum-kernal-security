// src/ebpf_monitor.rs
use bcc::BccError;
use bcc::core::BPF;
use std::sync::Arc;
use dashmap::DashMap;
use std::collections::HashMap;

pub struct EBPFMonitor {
    bpf: Arc<BPF>,
    syscall_stats: Arc<DashMap<u32, SyscallStat>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SyscallStat {
    pub count: u64,
    pub avg_duration_ns: u64,
    pub error_rate: f32,
    pub suspicious_score: f32,
}

impl EBPFMonitor {
    pub fn new() -> Result<Self, BccError> {
        // eBPF program that hooks syscalls
        let bpf_code = r#"
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(syscall_start, u64, u64);
BPF_HASH(syscall_count, u32, u64);
BPF_HASH(syscall_errors, u32, u64);
BPF_PERF_OUTPUT(events);

struct data_t {
    u32 pid;
    u32 syscall;
    u64 duration;
    u32 retval;
};

int syscall_entry(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    syscall_start.update(&pid_tgid, &ts);
    return 0;
}

int syscall_exit(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *tsp = syscall_start.lookup(&pid_tgid);
    
    if (tsp == 0) {
        return 0;
    }
    
    u64 duration = bpf_ktime_get_ns() - *tsp;
    u32 syscall_id = PT_REGS_PARM1(ctx);
    
    // Update counters
    u64 zero = 0, *count;
    count = syscall_count.lookup_or_init(&syscall_id, &zero);
    (*count)++;
    
    // Check for errors (negative return values)
    long retval = PT_REGS_RC(ctx);
    if (retval < 0) {
        u64 *errors;
        errors = syscall_errors.lookup_or_init(&syscall_id, &zero);
        (*errors)++;
    }
    
    // Send to userspace if suspicious
    if (duration > 1000000000) { // >1 second
        struct data_t data = {};
        data.pid = pid_tgid >> 32;
        data.syscall = syscall_id;
        data.duration = duration;
        data.retval = retval;
        events.perf_submit(ctx, &data, sizeof(data));
    }
    
    syscall_start.delete(&pid_tgid);
    return 0;
}
"#;

        let mut bpf = BPF::new(bpf_code)?;
        
        // Attach probes
        bpf.attach_kprobe("syscall_entry", "syscall_entry")?;
        bpf.attach_kretprobe("syscall_exit", "syscall_exit")?;
        
        Ok(Self {
            bpf: Arc::new(bpf),
            syscall_stats: Arc::new(DashMap::new()),
        })
    }
    
    pub fn start_monitoring(&self) -> tokio::task::JoinHandle<()> {
        let stats = self.syscall_stats.clone();
        let bpf = self.bpf.clone();
        
        tokio::spawn(async move {
            let mut perf_map = bpf.table("events").unwrap().into_perf().unwrap();
            
            loop {
                for data in perf_map.read().unwrap() {
                    let pid = u32::from_ne_bytes(data[0..4].try_into().unwrap());
                    let syscall = u32::from_ne_bytes(data[4..8].try_into().unwrap());
                    let duration = u64::from_ne_bytes(data[8..16].try_into().unwrap());
                    
                    // Update real-time stats
                    let mut stat = stats.entry(syscall).or_insert(SyscallStat {
                        count: 0,
                        avg_duration_ns: 0,
                        error_rate: 0.0,
                        suspicious_score: 0.0,
                    });
                    
                    stat.count += 1;
                    stat.avg_duration_ns = (stat.avg_duration_ns + duration) / 2;
                    
                    // Calculate suspiciousness
                    stat.suspicious_score = Self::calculate_suspicious_score(&stat);
                    
                    if stat.suspicious_score > 0.8 {
                        tracing::warn!(
                            "Suspicious syscall detected: {} (score: {:.2})",
                            syscall, stat.suspicious_score
                        );
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        })
    }
    
    fn calculate_suspicious_score(stat: &SyscallStat) -> f32 {
        let mut score = 0.0;
        
        // High error rate = suspicious
        if stat.error_rate > 0.3 {
            score += 0.4;
        }
        
        // Unusually long duration = suspicious
        if stat.avg_duration_ns > 100_000_000 { // >100ms
            score += 0.3;
        }
        
        // High frequency = suspicious (potential DoS)
        if stat.count > 1000 {
            score += 0.3;
        }
        
        score.min(1.0)
    }
}
