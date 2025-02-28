const mongoose = require('mongoose');
const config = require('../config/index');

const dbConnect = async () =>{
    try{
        mongoose.set('strictQuery',false);
        const conn = await mongoose.connect(config.CONNECTION_STRING);
        console.log("Database connected to host:"+conn.connection.host);

    }catch(error){
        console.log(`Error: ${error}`);
    }
}

module.exports = dbConnect;