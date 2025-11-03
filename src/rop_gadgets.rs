use crate::opts::Opts;
use crate::patch_bin;

use std::fs::File;
use std::io;
use std::process::Command;

use colored::Colorize;
use snafu::ResultExt;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[snafu(display("ROPGadget failed with nonzero exit status"))]
    ROPGadget,

    #[snafu(display("ROPGadget failed to start; please install ROPGadget: {}", source))]
    ROPGadgetExec { source: io::Error },

    #[snafu(display("failed opening gadgets output file: {}", source))]
    OpenFile { source: io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

/// Extract ROP gadgets from binary using ROPGadget and save to gadgets.txt
pub fn extract_rop_gadgets(opts: &Opts) -> Result<()> {
    if let Some(bin_patched) = patch_bin::bin_patched_path(opts) {
        println!(
            "{}",
            format!(
                "extracting ROP gadgets from {}",
                bin_patched.to_string_lossy().bold()
            )
            .green()
        );

        File::create("gadgets.txt").context(OpenFileSnafu)?;

        let output = Command::new("ROPgadget")
            .arg("--binary")
            .arg(&bin_patched)
            .output()
            .context(ROPGadgetExecSnafu)?;

        if !output.status.success() {
            return Err(Error::ROPGadget);
        }

        std::fs::write("gadgets.txt", output.stdout).context(OpenFileSnafu)?;

        println!("{}", format!("ROP gadgets saved to gadgets.txt").green());
    }

    Ok(())
}
