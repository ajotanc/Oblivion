// Em release, não abre uma janela de console junto com a interface.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    oblivion_app_lib::run()
}
