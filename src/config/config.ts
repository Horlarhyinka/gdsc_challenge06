import dotenv from "dotenv"

dotenv.config()

const db = {
    uri: process.env.DB_URI || "mongodb://localhost:27017/gdsc"
}

const server = { 
    port: process.env.SERVER_PORT || 8000, 
    saltRound: process.env.SERVER_SALT_ROUND || 18,
    secret: process.env.SERVER_SECRET || "MY_SUPER_LONG_SECRET_",
}


export default {server, db}