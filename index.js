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
    origin: ["http://localhost:5173", "https://mhfins.vercel.app"], credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
}))
app.use(express.json())
app.use(cookieParser())



const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.jt5df8u.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
// const uri = "mongodb://localhost:27017";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

const db = client.db("mh_fins")
const userColl = db.collection("users")

async function verifyJWT(req, res, next) {
    const token = req.cookies?.token || req.headers?.authorization?.split(" ")[1]
    if (!token) {
        return res.status(401).send({ message: "unauthorize user" })
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send({ message: "invalid token user | forbidden access" })
        }
        req.user = decoded;
        next()
    })
}

async function run() {
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
            const result = await userColl.insertOne({ name, email, pin: hashedPin, number, role: "user" })
            console.log(result)
            // generate token 
            const token = await generateToken(name, email, number, result?.insertedId?.toString())
            res
                .status(200)
                .cookie("token", token, cookieOptions)
                .send(result)
        })
        // log in user
        app.post("/api/login", async (req, res) => {
            const { email, number, pin } = req.body;
            // check if all credentials are provided
            if (!email && !number) {
                return res.status(400).send({ message: "email or phone number required" })
            }
            if (!pin) {
                return res.status(400).send({ message: "invalid pin" })
            }
            // find the user in db
            const user = await userColl.findOne({ $or: [{ email }, { number }] })
            if (!user) {
                return res.status(404).send({ message: "Wrong credentials. User Not found" })
            }
            // verify pin
            const verifyPin = await bcrypt.compare(pin, user?.pin);
            if (!verifyPin) {
                return res.status(401).send({ message: "Wrong Pin" })
            }
            // crate token
            const token = await generateToken(user.name, user?.email, user?.number, user?._id.toString())
            // prepare data to send---
            // remove pin from user Object
            delete user?.pin;
            res
                .status(200)
                .cookie("token", token, cookieOptions)
                .send(user)
        })
        // Logout
        app.get('/api/logout', async (req, res) => {
            try {
                res
                    .clearCookie('token', cookieOptions)
                    .send({ success: true })
                console.log('Logout successful')
            } catch (err) {
                res.status(500).send(err)
            }
        })
        // get user
        app.get("/api/user", verifyJWT, async (req, res) => {
            console.log(req?.user)
            const query = { email: req?.user?.email }
            const options = { projection: { pin: 0 } }
            const user = await userColl.findOne(query, options)
            res.send(user)
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
    return hashedPassword;
}

const cookieOptions = {
    httpOnly: true,
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
    secure: process.env.NODE_ENV === 'production' ? true : false
}