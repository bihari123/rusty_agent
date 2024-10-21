use super::{scheduled_job::Job, sqlite::Database};
use lazy_static::lazy_static;
use std::{
    collections::BinaryHeap,
    sync::{Arc, Mutex},
};

lazy_static! {
    pub static ref GLOBAL_JOBS_HEAP: Arc<Mutex<BinaryHeap<Job>>> =
        Arc::new(Mutex::new(BinaryHeap::new()));
    pub static ref DATABASE_OBJ: Arc<Mutex<Database>> =
        match Database::new("./rusty_assets/db.sqlite") {
            Ok(db) => Arc::new(Mutex::new(db)),
            Err(err) => {
                panic!("Error while creating a database object {err}");
            }
        };
    pub static ref PORT_NUMBER: Arc<Mutex<u16>> = Arc::new(Mutex::new(0));
}
