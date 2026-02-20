use ipp::prelude::*;
use std::{
    borrow::Cow,
    collections::HashMap,
    io::Cursor,
    num::{ParseIntError, TryFromIntError},
    sync::LazyLock,
};
use thiserror::Error;

const DUPLEX_OPTIONS: LazyLock<HashMap<&str, IppValue>> = LazyLock::new(|| {
    HashMap::from([
        ("1sided", IppValue::Keyword("1Sided".to_string())),
        ("2sided", IppValue::Keyword("2Sided".to_string())),
    ])
});
const COLOR_OPTIONS: LazyLock<HashMap<&str, IppValue>> = LazyLock::new(|| {
    HashMap::from([
        ("auto", IppValue::Keyword("Auto".to_string())),
        ("color", IppValue::Keyword("Color".to_string())),
        ("grayscale", IppValue::Keyword("Grayscale".to_string())),
    ])
});
const ORIENTATION: LazyLock<HashMap<&str, IppValue>> = LazyLock::new(|| {
    HashMap::from([
        ("portrait", IppValue::Integer(3)),
        ("landscape", IppValue::Integer(4)),
    ])
});
const SIZE: LazyLock<HashMap<&str, IppValue>> = LazyLock::new(|| {
    HashMap::from([
        ("A4", IppValue::Keyword("A4".to_string())),
        ("A3", IppValue::Keyword("A3".to_string())),
    ])
});

pub struct PrintOptions<'a> {
    pub duplex: Cow<'a, str>,
    pub color: Cow<'a, str>,
    pub size: Cow<'a, str>,
    pub page_range: Cow<'a, str>,
    pub orientation: Cow<'a, str>,
    pub copies: usize,
}

#[derive(Debug, Error)]
pub enum PrintOptionsParseError {
    #[error("error parsing integer: {0}")]
    ParseIntError(#[from] ParseIntError),
    #[error("error converting integer: {0}")]
    TryFromIntError(#[from] TryFromIntError),
    #[error("invalid option for {field}: {value}")]
    InvalidPrintOption {
        field: Cow<'static, str>,
        value: String,
    },
}

impl<'a> PrintOptions<'a> {
    fn into_print_job_attributes(self) -> Result<Vec<IppAttribute>, PrintOptionsParseError> {
        use PrintOptionsParseError::InvalidPrintOption;

        let mut attributes = Vec::new();

        if self.duplex != "none" {
            attributes.push(IppAttribute::new(
                "KMDuplex",
                DUPLEX_OPTIONS
                    .get(self.duplex.as_ref())
                    .ok_or(InvalidPrintOption {
                        field: "duplex".into(),
                        value: self.duplex.into_owned(),
                    })?
                    .clone(),
            ));
        }

        if self.color != "auto" {
            attributes.push(IppAttribute::new(
                "SelectColor",
                COLOR_OPTIONS
                    .get(self.color.as_ref())
                    .ok_or(InvalidPrintOption {
                        field: "color".into(),
                        value: self.color.into_owned(),
                    })?
                    .clone(),
            ));
        }

        attributes.push(IppAttribute::new(
            "PageSize",
            SIZE.get(self.size.as_ref())
                .ok_or(InvalidPrintOption {
                    field: "size".into(),
                    value: self.size.into_owned(),
                })?
                .clone(),
        ));

        if !self.page_range.is_empty() {
            for range in self.page_range.split(',') {
                if let Some((min, max)) = range.split_once('-') {
                    let min = min.parse()?;
                    let max = max.parse()?;
                    attributes.push(IppAttribute::new(
                        "page-ranges",
                        IppValue::RangeOfInteger { min, max },
                    ));
                } else {
                    let page = range.parse()?;
                    attributes.push(IppAttribute::new(
                        "page-ranges",
                        IppValue::RangeOfInteger {
                            min: page,
                            max: page,
                        },
                    ));
                }
            }
        }

        attributes.push(IppAttribute::new(
            "orientation",
            ORIENTATION
                .get(self.orientation.as_ref())
                .ok_or(InvalidPrintOption {
                    field: "orientation".into(),
                    value: self.orientation.into_owned(),
                })?
                .clone(),
        ));

        attributes.push(IppAttribute::new(
            IppAttribute::COPIES,
            IppValue::Integer(self.copies.try_into()?),
        ));

        Ok(attributes)
    }
}

pub struct Printer {
    client: AsyncIppClient,
}

#[derive(Debug, Error)]
pub enum PrintError {
    #[error("ipp error: {0}")]
    IppError(#[from] IppError),
    #[error("error parsing print options: {0}")]
    PrintOptionsParseError(#[from] PrintOptionsParseError),
}

impl Printer {
    pub fn new(uri: Uri) -> Self {
        Printer {
            client: AsyncIppClient::new(uri.clone()),
        }
    }

    pub async fn print(&self, options: PrintOptions<'_>, payload: &[u8]) -> Result<(), PrintError> {
        let payload = IppPayload::new(Cursor::new(Box::<[_]>::from(payload)));
        let req = IppOperationBuilder::print_job(self.client.uri().clone(), payload)
            .attributes(options.into_print_job_attributes()?)
            .build();
        self.client.send(req).await?;
        Ok(())
    }
}
