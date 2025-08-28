import express from "express";
import dotenv from "dotenv";
import connectdb from "./database/db.js";
import userRoute from "./routes/user.route.js"
import blogRoute from "./routes/blog.route.js"
import cors from "cors"
import cookieParser from "cookie-parser"

dotenv.config()
const app = express()
app.use(express.json());
app.use(cookieParser())
app.use(express.urlencoded({extended:true}))
app.use(cors({
    origin:"https://blog-website-khaki-one.vercel.app",
    credentials:true
}))

const PORT = process.env.PORT || 3000

app.use("/api/v1/user",userRoute)
app.use("/api/v1/blog",blogRoute)

app.listen(PORT,() => {
    connectdb()
    console.log(`server listen at port ${PORT}`);
    
})