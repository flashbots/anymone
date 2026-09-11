use std::{path::Path, sync::Mutex};

use anyhow::{ensure, Result};
use anymone_eth_service::{EpochBatch, FeedDescriptor, ReplyPacket};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

pub struct ResponseBoard {
    descriptor: FeedDescriptor,
    connection: Mutex<Connection>,
}

impl ResponseBoard {
    pub fn open(path: &Path, descriptor: FeedDescriptor) -> Result<Self> {
        descriptor.validate()?;
        let connection = Connection::open(path)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS feed_config (id INTEGER PRIMARY KEY CHECK(id=1), descriptor TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS responses (epoch INTEGER NOT NULL, locator BLOB NOT NULL, service TEXT NOT NULL,
                packet BLOB NOT NULL, PRIMARY KEY(epoch,locator));")?;
        let serialized = serde_json::to_string(&descriptor)?;
        connection.execute("INSERT OR IGNORE INTO feed_config(id,descriptor) VALUES(1,?1)", [&serialized])?;
        let existing: String = connection.query_row("SELECT descriptor FROM feed_config WHERE id=1", [], |r| r.get(0))?;
        ensure!(existing == serialized, "feed parameters changed; use a new feed and database");
        Ok(Self { descriptor, connection: Mutex::new(connection) })
    }

    pub fn descriptor(&self) -> &FeedDescriptor { &self.descriptor }

    pub fn enqueue(&self, service: &str, quota_bytes: u32, epoch: u64, packet: &ReplyPacket, now: u64) -> Result<()> {
        ensure!(packet.binding.feed == self.descriptor.feed && packet.binding.epoch == epoch, "invalid response binding");
        ensure!(epoch == self.descriptor.epoch(now)?, "publication slot is not open");
        let oldest = epoch.saturating_sub(u64::from(self.descriptor.retained_epochs));
        let locator = packet.binding.locator.as_slice();
        let bytes = bincode::serialize(packet)?;
        let mut connection = self.connection.lock().map_err(|_| anyhow::anyhow!("board lock poisoned"))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("DELETE FROM responses WHERE epoch<?1", [oldest])?;
        let existing: Option<(String, Vec<u8>)> = transaction.query_row(
            "SELECT service,packet FROM responses WHERE epoch=?1 AND locator=?2", params![epoch, locator],
            |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        if let Some((owner, existing)) = existing {
            ensure!(owner == service && existing == bytes, "conflicting publication retry");
            return Ok(());
        }
        let total: u64 = transaction.query_row("SELECT COALESCE(SUM(length(packet)),0) FROM responses WHERE epoch=?1",
            [epoch], |r| r.get(0))?;
        let owned: u64 = transaction.query_row("SELECT COALESCE(SUM(length(packet)),0) FROM responses WHERE epoch=?1 AND service=?2",
            params![epoch, service], |r| r.get(0))?;
        let framing = bincode::serialized_size(&EpochBatch { feed: self.descriptor.feed, epoch, responses: vec![] })?;
        ensure!(total + bytes.len() as u64 + framing <= u64::from(self.descriptor.max_epoch_bytes)
            && owned + bytes.len() as u64 <= u64::from(quota_bytes), "publication capacity exhausted");
        transaction.execute("INSERT INTO responses(epoch,locator,service,packet) VALUES(?1,?2,?3,?4)",
            params![epoch, locator, service, bytes])?;
        transaction.commit()?;
        Ok(())
    }

    pub fn epoch(&self, epoch: u64, now: u64) -> Result<EpochBatch> {
        let current = self.descriptor.epoch(now)?;
        ensure!(epoch < current && current - epoch <= u64::from(self.descriptor.retained_epochs),
            "epoch outside retention");
        let connection = self.connection.lock().map_err(|_| anyhow::anyhow!("board lock poisoned"))?;
        let oldest = current.saturating_sub(u64::from(self.descriptor.retained_epochs));
        connection.execute("DELETE FROM responses WHERE epoch<?1", [oldest])?;
        let mut statement = connection.prepare("SELECT packet FROM responses WHERE epoch=?1 ORDER BY locator")?;
        let rows = statement.query_map([epoch], |r| r.get::<_, Vec<u8>>(0))?;
        let mut responses = Vec::new();
        for row in rows { responses.push(bincode::deserialize(&row?)?); }
        Ok(EpochBatch { feed: self.descriptor.feed, epoch, responses })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anymone_eth_service::{crypto::DeliveryBinding, crypto::SealedResponse};

    fn packet(locator: u8, bytes: usize) -> ReplyPacket {
        ReplyPacket { binding: DeliveryBinding { feed: [1;32], epoch:100, locator:[locator;32] },
            sealed: SealedResponse { nonce:[0;24], ciphertext:vec![9;bytes] } }
    }

    #[test]
    fn epochs_store_whole_responses_with_byte_limits_and_stable_retries() {
        let descriptor = FeedDescriptor { feed: [1; 32], genesis_time: 0, epoch_seconds: 10,
            max_epoch_bytes: 1024, retained_epochs: 3 };
        let board = ResponseBoard::open(Path::new(":memory:"), descriptor.clone()).unwrap();
        let response = packet(9, 100);
        let quota = bincode::serialized_size(&response).unwrap() as u32;
        board.enqueue("provider", quota, 100, &response, 1001).unwrap();
        board.enqueue("provider", quota, 100, &response, 1001).unwrap();
        assert!(board.enqueue("provider", quota, 100, &packet(8,100), 1001).is_err());
        assert!(board.enqueue("other", 2000, 100, &packet(8,900), 1001).is_err());
        assert!(board.enqueue("provider", quota, 100, &packet(9,101), 1001).is_err());
        assert!(board.epoch(100, 1001).is_err());
        let batch = board.epoch(100, 1010).unwrap();
        assert_eq!(bincode::serialize(&batch.responses[0]).unwrap(), bincode::serialize(&response).unwrap());
        assert_eq!(bincode::serialize(&batch).unwrap(), bincode::serialize(&board.epoch(100, 1011).unwrap()).unwrap());
        assert!(bincode::serialized_size(&batch).unwrap() < 1024);
        batch.validate(&descriptor, 100, 1011).unwrap();
        assert!(board.enqueue("provider", quota, 100, &response, 1010).is_err());
        assert!(board.epoch(100, 1040).is_err());
        let empty = board.epoch(103, 1040).unwrap();
        assert!(empty.responses.is_empty());
        empty.validate(&descriptor, 103, 1040).unwrap();
    }
}
