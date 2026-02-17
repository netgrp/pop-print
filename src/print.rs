use std::{
    collections::HashMap,
    fs::{self, File},
    io::Write,
    ops::{Deref, DerefMut},
    path::Path,
    process::Command,
    sync::LazyLock,
    time::UNIX_EPOCH,
};
use thiserror::Error;

const UPLOAD_FOLDER: &str = "/tmp/";
const CUPS_SERVER_HOST: Option<&str> = None;
const PRINTER: &str = "Konica_Minolta";
const DUPLEX_OPTIONS: LazyLock<HashMap<&str, &str>> =
    LazyLock::new(|| HashMap::from([("1sided", "1Sided"), ("2sided", "2Sided")]));
const COLOR_OPTIONS: LazyLock<HashMap<&str, &str>> =
    LazyLock::new(|| HashMap::from([("auto", ""), ("color", "Color"), ("grayscale", "Grayscale")]));
const ORIENTATION: LazyLock<HashMap<&str, &str>> = LazyLock::new(|| {
    HashMap::from([
        ("portrait", "orientation-requested=3"),
        ("landscape", "orientation-requested=4"),
    ])
});
const SIZE: LazyLock<HashMap<&str, &str>> =
    LazyLock::new(|| HashMap::from([("A4", "A4"), ("A3", "A3")]));

pub struct PrintOptions<'a> {
    pub duplex: &'a str,
    pub color: &'a str,
    pub size: &'a str,
    pub page_range: &'a str,
    pub orientation: &'a str,
    pub copies: usize,
}

pub struct PrinterCommand<'a> {
    command: Command,
    pdf: &'a [u8],
}

#[derive(Debug, Error)]
pub enum PrinterCommandError {
    #[error("error spawning command: {0}")]
    Spawn(std::io::Error),
    #[error("error whilst waiting for command: {0}")]
    WaitForFinish(std::io::Error),
    #[error("lp exited with non-zero status")]
    Lp,
    #[error("error saving input file: {0}")]
    InputFile(std::io::Error),
}

impl<'a> PrinterCommand<'a> {
    pub fn build(options: PrintOptions<'_>, pdf: &'a [u8]) -> Self {
        let mut command = Command::new("lp" /*"/usr/bin/lp"*/);

        if let Some(server) = CUPS_SERVER_HOST {
            command.args(["-h", &server]);
        }

        command.args(["-d", PRINTER]);

        if options.duplex != "none" {
            command.args([
                "-o",
                &format!("KMDuplex={}", DUPLEX_OPTIONS[options.duplex]),
            ]);
        }

        if options.color != "auto" {
            command.args([
                "-o",
                &format!("SelectColor={}", COLOR_OPTIONS[options.color]),
            ]);
        }

        command.args(["-o", &format!("PageSize={}", SIZE[options.size])]);

        if !options.page_range.is_empty() {
            command.args(["-P", options.page_range]);
        }

        command.args(["-o", ORIENTATION[options.orientation]]);

        command.args(["-n", &options.copies.to_string()]);

        command.arg("--");

        PrinterCommand { command, pdf }
    }

    pub fn run(self) -> Result<(), PrinterCommandError> {
        use PrinterCommandError::*;

        let Self { mut command, pdf } = self;

        let file_name = UNIX_EPOCH.elapsed().unwrap().as_millis().to_string();
        let file_path = Path::new(UPLOAD_FOLDER).join(file_name);

        let mut file = RemoveOnDrop::create_new(file_path.clone()).map_err(InputFile)?;
        file.write_all(pdf).map_err(InputFile)?;

        command.arg(file_path);

        let mut child = command.spawn().map_err(Spawn)?;
        let status = child.wait().map_err(WaitForFinish)?;
        if status.success() {
            eprintln!("successfully printed");
            Ok(())
        } else {
            Err(Lp)
        }
    }
}

struct RemoveOnDrop<P: AsRef<Path>>(P, File);

impl<P: AsRef<Path>> RemoveOnDrop<P> {
    fn create_new(path: P) -> std::io::Result<Self> {
        let file = File::create_new(&path)?;
        Ok(Self(path, file))
    }
}

impl<P: AsRef<Path>> Deref for RemoveOnDrop<P> {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.1
    }
}

impl<P: AsRef<Path>> DerefMut for RemoveOnDrop<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.1
    }
}

impl<P: AsRef<Path>> Drop for RemoveOnDrop<P> {
    fn drop(&mut self) {
        let RemoveOnDrop(path, _) = self;
        let _ = fs::remove_file(path);
    }
}
