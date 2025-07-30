#[rustfmt::skip]
mod config;
mod gui;

use std::sync::Arc;

fn main() {
    println!("Hello, world!");
    print!("Starting GUI thread...\t");
    // this allows the D-Bus service to signal to the GUI to draw a window for
    // executing the credential flow.
    let (dbus_to_gui_tx, dbus_to_gui_rx) = async_std::channel::unbounded();
    gui::start_gui_thread(dbus_to_gui_rx, Arc::new(cred_client));
    println!(" ✅");
}

trait UiControlService {
    fn launch_ui(&self);
    fn send_state_changed(&self);
}
