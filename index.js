require("dotenv").config()
const express = require('express')
const { MongoClient, ServerApiVersion } = require('mongodb');
const jwt = require("jsonwebtoken")
const cookieParser = require('cookie-parser')
const cors = require("cors")
const bcrypt = require("bcrypt")
const app = express()
const port = process.env.PORT || 5000;

// middlewares
app.use(cors({
    origin: ["http://localhost:5173"], credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
}))
app.use(express.json())
app.use(cookieParser())



// const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.jt5df8u.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const uri = "mongodb://localhost:27017";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    const db = client.db("mh_fins")
    const userColl = db.collection("users")

    try {
        // user related apis
        // register user
        app.post("/api/register", async (req, res) => {
            const { name, email, number, pin } = req.body;
            if (!name || !email || !number || !pin) {
                return res.status(400).send({ message: "All fields are required" })
            }
            // check if user already exists
            const isExist = await userColl.findOne({ $or: [{ email }, { number }] })
            if (isExist) {
                return res.status(409).send({ message: "User already exists with this email or number" })
            }
            // hash pin
            const hashedPin = await hashPassword(pin)
            // insert user in database
            const result = await userColl.insertOne({ name, email, pin: hashedPin, number })
            console.log(result)
            // generate token 
            const token = await generateToken(name, email, number, result?.insertedId?.toString())
            res
                .status(200)
                .cookie("token", token, cookieOptions)
                .send(result)
        })

        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send('Hello World!')
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})


// utils
async function generateToken(name, email, number, _id) {
    const token = jwt.sign(
        { name, email, number, _id },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
    )
    return token
}
async function hashPassword(password) {
    const hashedPassword = await bcrypt.hash(password, 10)
    return hashedPassword
}

const cookieOptions = {
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
    secure: process.env.NODE_ENV === 'production' ? true : false
}