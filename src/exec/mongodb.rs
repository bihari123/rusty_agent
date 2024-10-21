use mongodb::{bson::doc, options::ClientOptions, Client};

pub async fn _sync_mongodb() -> mongodb::error::Result<()> {
    // Replace the placeholder with your Atlas connection string
    let uri = "mongodb://localhost:27017";

    let client_options = ClientOptions::parse(uri).await?;
    // Create a new client and connect to the server
    let client = Client::with_options(client_options)?;
    // Send a ping to confirm a successful connection

    for db_name in client.list_database_names(None, None).await? {
        println!("{db_name}");
    }
    client
        .database("admin")
        .run_command(doc! {"ping": 1}, None)
        .await?;
    println!("Pinged your deployment. You successfully connected to MongoDB!");
    Ok(())
}
