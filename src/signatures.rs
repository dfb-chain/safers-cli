use redb::{Database, TableDefinition};
use std::path::PathBuf;

const SIGNATURES_TABLE: TableDefinition<&str, &str> = TableDefinition::new("signatures");

/// Get the path to the signatures database
fn get_db_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".safers-cli").join("signatures.redb")
}

/// Initialize the signatures database
pub fn init_db() -> Result<Database, Box<dyn std::error::Error>> {
    let db_path = get_db_path();
    
    // Create directory if it doesn't exist
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    
    let db = Database::create(&db_path)?;
    
    // Initialize table
    let write_txn = db.begin_write()?;
    {
        let _table = write_txn.open_table(SIGNATURES_TABLE)?;
    }
    write_txn.commit()?;
    
    Ok(db)
}

/// Open existing database
pub fn open_db() -> Result<Database, Box<dyn std::error::Error>> {
    let db_path = get_db_path();
    
    if !db_path.exists() {
        return init_db();
    }
    
    Ok(Database::open(&db_path)?)
}

/// Insert a signature into the database
#[allow(dead_code)]
pub fn insert_signature(
    db: &Database,
    hex_signature: &str,
    text_signature: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let write_txn = db.begin_write()?;
    {
        let mut table = write_txn.open_table(SIGNATURES_TABLE)?;
        table.insert(hex_signature, text_signature)?;
    }
    write_txn.commit()?;
    Ok(())
}

/// Lookup a signature in the database
pub fn lookup_signature(
    db: &Database,
    hex_signature: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(SIGNATURES_TABLE)?;
    
    match table.get(hex_signature)? {
        Some(value) => Ok(Some(value.value().to_string())),
        None => Ok(None),
    }
}

/// Get database statistics  
pub fn get_stats(db: &Database) -> Result<u64, Box<dyn std::error::Error>> {
    let read_txn = db.begin_read()?;
    let table = read_txn.open_table(SIGNATURES_TABLE)?;
    // Count by iterating through all entries
    let mut count = 0u64;
    let range = table.range::<&str>(..)?;
    for _ in range {
        count += 1;
    }
    Ok(count)
}

/// Response from 4byte.directory API
#[derive(serde::Deserialize, Debug)]
pub struct FourByteResponse {
    pub results: Vec<SignatureResult>,
    pub next: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct SignatureResult {
    #[allow(dead_code)]
    pub id: u64,
    pub text_signature: String,
    pub hex_signature: String,
}

/// Download signatures from 4byte.directory API
pub async fn sync_signatures(
    db: &Database,
    limit: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let mut url = "https://www.4byte.directory/api/v1/signatures/".to_string();
    let mut total_synced = 0;
    let mut page = 0;
    
    println!("Starting signature sync from 4byte.directory...");
    
    loop {
        if total_synced >= limit {
            break;
        }
        
        page += 1;
        println!("Fetching page {}... (synced: {})", page, total_synced);
        
        let response: FourByteResponse = client
            .get(&url)
            .send()
            .await?
            .json()
            .await?;
        
        // Batch insert signatures
        let write_txn = db.begin_write()?;
        {
            let mut table = write_txn.open_table(SIGNATURES_TABLE)?;
            for sig in &response.results {
                // Normalize hex signature (ensure 0x prefix and lowercase)
                let hex_sig = if sig.hex_signature.starts_with("0x") {
                    sig.hex_signature.to_lowercase()
                } else {
                    format!("0x{}", sig.hex_signature.to_lowercase())
                };
                
                table.insert(hex_sig.as_str(), sig.text_signature.as_str())?;
                total_synced += 1;
            }
        }
        write_txn.commit()?;
        
        if response.results.is_empty() || response.next.is_none() {
            break;
        }
        
        url = response.next.unwrap();
        
        // Rate limiting - be nice to the API
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
    
    println!("✓ Synced {} signatures", total_synced);
    Ok(total_synced)
}

/// Decode calldata by looking up the 4-byte selector
pub fn decode_calldata(
    db: &Database,
    calldata: &str,
) -> Result<Option<(String, String)>, Box<dyn std::error::Error>> {
    // Strip 0x prefix if present
    let data = calldata.strip_prefix("0x").unwrap_or(calldata);
    
    if data.len() < 8 {
        return Ok(None);
    }
    
    // Extract 4-byte selector (first 8 hex chars)
    let selector = format!("0x{}", &data[..8].to_lowercase());
    let params = if data.len() > 8 {
        format!("0x{}", &data[8..])
    } else {
        String::new()
    };
    
    match lookup_signature(db, &selector)? {
        Some(text_sig) => Ok(Some((text_sig, params))),
        None => Ok(None),
    }
}

