const express = require("express")
const cors = require("cors")
const dotenv = require("dotenv")
const session = require("express-session")
const passport = require("passport")
const connectDB = require("./config/database")
const authRoutes = require("./routes/auth")

dotenv.config()

const app = express()

// Connect to MongoDB
connectDB()

// Middleware
app.use(
  cors({
    origin: [
      process.env.CLIENT_URL || "http://localhost:3000",
      "http://localhost:3000",
      "https://tnttierion.com"
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
  }),
)
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

// Session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set to true in production with HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  }),
)

// Passport middleware
app.use(passport.initialize())
app.use(passport.session())

// Passport config
require("./config/passport")(passport)

// Routes
app.use("/api/auth", authRoutes)

// Health check
app.get("/", (req, res) => {
  res.json({ message: "Adventure Safari API is running!" })
})

const PORT = process.env.PORT || 5000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
