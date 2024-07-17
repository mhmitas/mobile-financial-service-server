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
const balanceColl = db.collection("balances")
const transactionColl = db.collection("transactions")

async function verifyJWT(req, res, next) {
    const token = req.cookies?.token || req.headers?.authorization?.split(" ")[1]
    if (!token) {
        return res.status(401).send({ message: "unauthorize user" })
    }
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).send({ message: "invalid token, Mr. User | forbidden access" })
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
            const result = await userColl.insertOne({ name, email, pin: hashedPin, number, role: "pending", status: "pending" })
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
        app.post('/api/logout', async (req, res) => {
            try {
                res
                    .clearCookie('token', cookieOptions)
                    .send({ success: true })
                console.log('Logout successful')
            } catch (err) {
                res.status(500).send(err)
            }
        })
        // get current user
        app.get("/api/current-user", verifyJWT, async (req, res) => {
            const query = { email: req?.user?.email }
            const options = { projection: { pin: 0 } }
            const user = await userColl.findOne(query, options)
            res.send(user)
        })


        // user related apis
        // want to become an agent endpoint
        app.patch("/api/user/become-agent-request/:email", async (req, res) => {
            const email = req.params?.email
            const { wantToBecomeAgent, message } = req.body;
            const updateDoc = { $set: { wantToBecomeAgent, message } }
            const result = await userColl.updateOne({ email }, updateDoc)
            res.status(200).send(result)
        })
        // get total balance
        app.get("/api/user/total-balance/:email", async (req, res) => {
            const email = req.params.email;
            const result = await balanceColl.findOne({ email })
            res.send(result)
        })


        // agent related api's
        app.get("/api/agent/total-balance/:email", async (req, res) => {
            const email = req.params.email;
            const result = await balanceColl.findOne({ email })
            res.send(result)
        })


        // admin related apis 
        // get all users
        app.get("/api/admin/all-users", async (req, res) => {
            let query = {}
            if (req.query?.status) {
                query = { ...query, status: req.query?.status }
            }
            if (req.query?.role) {
                query = { ...query, role: req.query?.role }
            }
            const options = { projection: { pin: 0 } }
            const result = await userColl.find(query, options).toArray()
            res
                .status(200)
                .send(result)
        })
        // approve a user 
        app.patch("/api/admin/approve-user/:email", async (req, res) => {
            const email = req.params?.email;
            const { role, status = "verified", bonusAmount } = req.body;
            // create a balance data for the user
            const balance = {
                balance: bonusAmount,
                email: email,
            }
            const insertInBalanceColl = await balanceColl.insertOne(balance);
            // create data to update user role from pending to user
            const updateDoc = { $set: { role, status } }
            const updateUserRoleResult = await userColl.updateOne({ email }, updateDoc)
            // send response
            res.status(200).send({ updateUserRoleResult, insertInBalanceColl })
        })
        // change user role from user to agent 
        app.patch("/api/admin/make-agent/:email", async (req, res) => {
            const email = req.params?.email;
            const { bonusAmount } = req.body;
            // update users role
            const updateDoc = {
                $set: { role: "agent" },
                $unset: { wantToBecomeAgent: "", message: "" }
            }
            const result = await userColl.updateOne({ email }, updateDoc);
            // give bonus money
            // get user's balance
            const balance = await balanceColl.findOne({ email }, { projection: { balance: 1, _id: 0 } })
            if (!balance) {
                return res.status(404).send({ message: "account not found" })
            }
            const newBalance = parseFloat(bonusAmount) + parseFloat(balance?.balance)
            // add bonus balance
            const updateDoc2 = { $set: { balance: newBalance } }
            const bonusResult = await balanceColl.updateOne({ email }, updateDoc2)
            res.status(200).send({ result, bonusResult })
        })
        // get user's who are want to be agent
        app.get("/api/admin/pending-agent-requests", async (req, res) => {
            const query = { wantToBecomeAgent: true }
            const result = await userColl.find(query, { projection: { pin: 0 } }).toArray()
            res.status(200).send(result)
        })

        // send money api
        app.post("/api/send-money", async (req, res) => {
            const { recipientNumber, senderNumber, senderPin, amount } = req.body;
            if (recipientNumber === senderNumber) {
                return res.status(400).send({ message: "You cannot send money to your own account" })
            }
            if (parseFloat(amount) < 50) {
                return res.status(400).send({ message: "Less than 50 taka is not allowed" })
            }
            // get the sender data from db
            const sender = await userColl.findOne({ number: senderNumber })
            if (!sender) {
                return res.status(404).send({ message: "sender not found" })
            }
            const verifyPin = await bcryptPinVerify(senderPin, sender?.pin)
            if (!verifyPin) {
                return res.status(400).send({ message: "Please give a valid pin" })
            }
            // get the recipient data form db
            const recipient = await userColl.findOne({ number: recipientNumber })
            if (!recipient) {
                return res.status(404).send({ message: "recipient not found" })
            }
            // get the sender balance
            const senderBalanceData = await balanceColl.findOne({ email: sender?.email })
            let senderCurrentBalance = parseFloat(senderBalanceData?.balance)
            // get the recipient balance
            const recipientBalanceData = await balanceColl.findOne({ email: recipient?.email })
            let recipientCurrentBalance = parseFloat(recipientBalanceData?.balance)
            // cut money if payment is greater than 100
            let charge = 0;
            if (amount >= 100) {
                senderCurrentBalance = senderCurrentBalance - 5;
                charge = 5;
            }
            if (senderCurrentBalance < 40) {
                return res.status(400).send({ message: "You don't sufficient balance to send money" })
            }
            if (senderCurrentBalance - parseFloat(amount) < 40) {
                return res.status(400).send({ message: "Account must have at least 40 TK after sending money" })
            }
            // cut money from sender's balance and add to the recipient's balance
            const senderNewBalance = senderCurrentBalance - parseFloat(amount)
            const recipientNewBalance = recipientCurrentBalance + parseFloat(amount)
            console.log({ senderCurrentBalance, senderNewBalance, recipientCurrentBalance, recipientNewBalance })

            // update sender's balance
            const updateSenderBalance = await balanceColl.updateOne(
                { email: sender?.email },
                { $set: { balance: senderNewBalance } }
            )
            // update recipient's balance
            const updateRecipientBalance = await balanceColl.updateOne(
                { email: recipient?.email },
                { $set: { balance: recipientNewBalance } }
            )
            // create transaction
            const senderTransactionDoc = {
                senderEmail: sender?.email,
                recipientName: recipient?.name,
                recipientEmail: recipient?.email,
                recipientNumber: recipient?.number,
                amount: amount,
                charge,
                date: new Date()
            }
            recipientTransactionDoc = {
                recipientEmail: recipient?.email,
                senderName: sender?.name,
                senderEmail: sender?.email,
                senderNumber: sender?.number,
                amount: amount,
                date: new Date()
            }
            const transactionSaveResult = await transactionColl.insertMany([senderTransactionDoc, recipientTransactionDoc])
            res.send({ updateSenderBalance, updateRecipientBalance, transactionSaveResult })
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

async function bcryptPinVerify(pin, hashedPin) {
    const isVerified = await bcrypt.compare(pin, hashedPin)
    return isVerified
}