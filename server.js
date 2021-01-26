const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const {sequelize, User} = require('./models')
const session = require('express-session')

const sessionSettings = {
    secret: "best cohort ever",
    resave: false,
    saveUninitialized: true
}

app.use(express.json())
app.use(session(sessionSettings))

//This function checks for authorisation headers before allowing access
const protect = async (req, res, next) => {
    if(!req.headers.authorization) {
        res.sendStatus(403)
    } else { 
        const user = await User.findByPk(req.params.id)
        res.locals.user = user
        next()
    }
}

//Welcome page
app.get("/", async (req, res) => {
    res.send("Hello! Sign in here.")
})

//Creates a new user and hashes the password
app.post("/users", async (req, res) => {
    const user = await User.create(req.body)
    const encrypted_password = await bcrypt.hash(req.body.password, 10)
    user.password = encrypted_password
    await user.save()
    res.send(user)
})

//Displays a user based on ID
app.get('/users/:id', protect, async (req, res) => {
    console.log(req.session.id)
    res.locals.user ? res.send(res.locals.user) : res.sendStatus(404)
})

//Deletes a user based on ID
app.delete('/users/:id', (req, res) => {
    res.sendStatus(200)
})

app.listen(3000, () => {
    sequelize.sync().then(() => console.log("Ready for users"))
})