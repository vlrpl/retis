//! # Print
//!
//! Print is a simple post-processing command that just parses events and prints them back to
//! stdout

use std::{io::stdout, path::PathBuf, time::Duration};

use anyhow::Result;
use clap::Parser;

use crate::{
    cli::*,
    events::{file::FileEventsFactory, *},
    helpers::signals::Running,
    module::Modules,
    process::display::*,
};

/// Print stored events to stdout
#[derive(Parser, Debug, Default)]
#[command(name = "print")]
pub(crate) struct Print {
    /// File from which to read events.
    #[arg(default_value = "retis.data")]
    pub(super) input: PathBuf,
    #[arg(long, help = "Format used when printing an event.")]
    #[clap(value_enum, default_value_t=CliDisplayFormat::MultiLine)]
    pub(super) format: CliDisplayFormat,
    #[arg(long, help = "Print the time as UTC")]
    pub(super) utc: bool,
}

impl SubCommandParserRunner for Print {
    fn run(&mut self, _: Modules) -> Result<()> {
        // Create running instance that will handle signal termination.
        let run = Running::new();
        run.register_term_signals()?;

        // Create event factory.
        let mut factory = FileEventsFactory::new(self.input.as_path())?;

        // Format.
        let format = DisplayFormat::new()
            .multiline(self.format == CliDisplayFormat::MultiLine)
            .time_format(if self.utc {
                TimeFormat::UtcDate
            } else {
                TimeFormat::MonotonicTimestamp
            });

        // Formatter & printer for events.
        let mut output = PrintEvent::new(Box::new(stdout()), PrintEventFormat::Text(format));

        use EventResult::*;
        while run.running() {
            match factory.next_event(Some(Duration::from_secs(1)))? {
                Event(event) => output.process_one(&event)?,
                Eof => break,
                Timeout => continue,
            }
        }
        Ok(())
    }
}
