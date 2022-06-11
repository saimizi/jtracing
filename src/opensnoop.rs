#[allow(unused)]
use {
    anyhow::{Context, Error, Result},
    jlogger::{jdebug, jerror, jinfo, jwarn, JloggerBuilder},
    log::{debug, error, info, warn, LevelFilter},
    std::{
        fmt::Display,
        fs,
        path::{Path, PathBuf},
    },
    tokio::{
        fs::File,
        io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader},
        signal,
        sync::mpsc::{self, Receiver, Sender},
        task::JoinHandle,
    },
    tracelib::{trace_top_dir, writeln_str_file, Kprobe, TraceLog},
};

async fn async_main() -> Result<()> {
    JloggerBuilder::new()
        .max_level(log::LevelFilter::Debug)
        .log_runtime(true)
        .log_time(true)
        .log_time_format(jlogger::LogTimeFormat::TimeStamp)
        .build();

    let current_tracer = format!("{}/current_tracer", trace_top_dir().await?);

    writeln_str_file(&current_tracer, "nop", false).await?;

    let fns = vec!["do_sys_open"];
    for fname in fns {
        if let Ok(mut kp) = Kprobe::new(None, fname, None) {
            kp.add_arg("file=+0($arg2):string");
            kp.add_arg("flag=+0($arg3):x32");
            kp.add_arg("mode=+0($arg4):x32");
            kp.build().await?;
            kp.enable()
                .await
                .with_context(|| format!("Failed to enable kprobe: {}", kp.group()))?;

            let mut tlog = TraceLog::new().await?;

            println!("{:<12} {:15} {:<8} {}", "TimeStamp", "Task", "PID", "OpenedFile");
            println!("{}", "=".repeat(80));
            loop {
                tokio::select! {
                    //Ok(log) = tlog.trace_print() => print!("{}", log),
                     result = tlog.trace_fields() => {
                         match result {
                            Ok((task, pid, _cpu, _flag, ts, msg)) => {
                                let mut fname = String::new();
                                let mut flag = String::new();
                                let mut mode = String::new();
                                let mut itor = msg.split(' ').collect::<Vec<&str>>().into_iter();
                                itor.next();
                                itor.next();

                                fname.push_str(itor.next().unwrap());
                                flag.push_str(itor.next().unwrap());
                                mode.push_str(itor.next().unwrap());

                                println!("{:<12} {:15} {:<8} {:<30}",ts, task, pid, fname);
                            },
                            Err(e) => eprintln!("Error: {}", e),
                         }
                    },
                    Ok(()) = signal::ctrl_c() => {
                        let _ = kp.disable();
                        kp.exit().await;
                        break;
                    },

                }
            }

            tlog.terminate().await;

            return Ok(());
        }
    }

    Err(Error::msg("Failed to add a kprobe for execve."))
}

fn main() {
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        if let Err(e) = async_main().await {
            error!("Error: {}", e);
        }
    });

    rt.shutdown_background();
}
