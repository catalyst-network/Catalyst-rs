use std::sync::{Once, ONCE_INIT};
use fern;
use chrono::Local;

/// Initialize the global logger and log to `rest_client.log`.
///
/// Note that this is an idempotent function, so you can call it as many
/// times as you want and logging will only be initialized the first time.
#[no_mangle]
pub extern "C" fn initialize_logging() {
    static INITIALIZE: Once = ONCE_INIT;
    INITIALIZE.call_once(|| {
        fern::Dispatch::new()
            .format(|out, message, record| {
                out.finish(format_args!(
                    "{}[{}][{}] {}",
                    Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                    record.level(),
                    message,
                    if cfg!(windows) { "\r" } else { "" }
                ))
            })
            .level(log::LevelFilter::Debug)
            .chain(fern::log_file("rest_client.log").unwrap())
            .apply()
            .unwrap();
    });
}

/// Log an error and each successive thing which caused it.
pub fn backtrace(e: &Error) {
    error!("Error: {}", e);

    for cause in e.iter().skip(1) {
        warn!("\tCaused By: {}", cause);
    }
}
