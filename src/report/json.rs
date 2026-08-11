use anyhow::Result;
use std::io::Write;

use crate::ScanReport;

pub fn emit_json(report: &ScanReport, out: &mut impl Write) -> Result<()> {
    serde_json::to_writer_pretty(&mut *out, report)?;
    writeln!(out)?;
    Ok(())
}
