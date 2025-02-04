use std::fs::File;
use std::io;
use std::io::Error;
use std::io::prelude::*;
use std::collections::HashMap;
// use std::sync::Arc;
// use tokio::sync::RwLock;
use once_cell::sync::OnceCell;

use core::result::Result;


pub static CONFIG: OnceCell<HashMap<String, String>> = OnceCell::new();


pub fn read_conf (path: &str)
        -> Result<(), Error>
{
    // let mut config;
    // let mut config: Option<RwLockWriteGuard<'_, ConfigMap>> = None;
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);

    // let mut config = CONFIG.write().await;
    let mut temp_settings = HashMap::new();


    for line in reader.lines() {
        let mut configline = line?;

        //Skip the comment line with '#'
        let position = configline.trim().find('#');
        if position == Some(0) {
            continue;
        }

        //Remove string after '#'
        if let Some(pos) = configline.find('#') {
            configline = configline[..pos].trim().to_string();
        }

        //Key, Value pair
        if let Some(pos) = configline.find('=') {
            let key = configline[..pos].trim().to_string();
            let value = configline[pos+1..].trim().to_string();

            temp_settings.insert(key, value);
        }
    }

    CONFIG.set(temp_settings).expect("Failed to set config");
    Ok(())
}
