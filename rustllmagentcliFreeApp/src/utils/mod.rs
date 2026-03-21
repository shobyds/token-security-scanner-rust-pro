//! Utility modules

pub mod csv_todo;
pub mod formatter;
pub mod logger;

#[cfg(feature = "lmstudio")]
pub mod model_detector;
#[cfg(feature = "lmstudio")]
pub mod network_scanner;

pub use csv_todo::{
    CsvError, CsvFileInfo, CsvResult, CsvTaskRow, create_task_csv, create_temp_csv,
    delete_temp_csv, get_csv_info, parse_tasks_from_csv, parse_tasks_from_raw_text, read_temp_csv,
    validate_csv_format,
};
pub use logger::{init_logging, init_logging_stdout};

#[cfg(feature = "lmstudio")]
#[allow(dead_code)]
pub use model_detector::{ModelDetector, ModelDetectorError, detect_loaded_model};
#[cfg(feature = "lmstudio")]
#[allow(dead_code)]
pub use network_scanner::{NetworkScanner, scan_for_lm_studio, scan_for_lm_studio_default};
