const dotenv = require('dotenv').config();

const PORT = process.env.PORT;
const CONNECTION_STRING = process.env.CONNECTION_STRING;
const  ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const  REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const BACKEND_SERVER_PATH = process.env.BACKEND_SERVER_PATH;
const CLOUD_NAME = process.env.CLOUD_NAME;
const API_SECRET = process.env.API_SECRET;
const API_KEY = process.env.API_KEY;

module.exports = {
    PORT,
    CONNECTION_STRING,
    ACCESS_TOKEN_SECRET,
    REFRESH_TOKEN_SECRET,
    BACKEND_SERVER_PATH,
    CLOUD_NAME,
    API_SECRET,
    API_KEY
}