use std::sync::OnceLock;

use tokio::runtime::Runtime;

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub fn get() -> &'static Runtime {
    RUNTIME.get_or_init(|| Runtime::new().expect("Tokio runtime to start"))
}
