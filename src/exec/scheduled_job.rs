use std::{cmp::Ordering, time::SystemTime};

pub struct Job {
    pub name: String,
    pub execute_at: SystemTime,
    pub cron_expression: String,
    pub script_content: String,
    pub arguments: String,
    pub script_type: u64,
    pub opensearch_index: String,
    pub opensearch_enabled: u64,
}

impl PartialEq for Job {
    fn eq(&self, other: &Self) -> bool {
        self.execute_at.eq(&other.execute_at)
    }
}

impl Eq for Job {}

impl PartialOrd for Job {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        other.execute_at.partial_cmp(&self.execute_at)
    }
}

impl Ord for Job {
    fn cmp(&self, other: &Self) -> Ordering {
        self.execute_at.cmp(&other.execute_at)
    }
}
