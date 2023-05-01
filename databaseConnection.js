require('dotenv').config();

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;

const MongoClient = require("mongodb").MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true&w=majority`;

async function initDatabaseConnection() {
  try {
    const client = await MongoClient.connect(atlasURI, { useNewUrlParser: true, useUnifiedTopology: true });
    console.log("DB connection successful");
    const database = client.db(mongodb_database);
    return database;
  } catch (error) {
    console.error(error);
    throw error;
  }
}

module.exports = { initDatabaseConnection };
