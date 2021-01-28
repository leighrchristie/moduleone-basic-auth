const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const { sequelize, User } = require('./models')
//const session = require('express-session')
const jwt = require('express-jwt')
const jwks = require('jwks-rsa')
const fetch = require('node-fetch')
const atob = require('atob')

const jwtCheck = jwt({
    secret: jwks.expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: 'https://dev-ga5nq384.eu.auth0.com/.well-known/jwks.json'
    }),
    audience: 'http://localhost:3000/',
    issuer: 'https://dev-ga5nq384.eu.auth0.com/',
    algorithms: ['RS256']
})

app.use(express.json())

// const sessionSettings = {
//     secret: "best cohort ever",
//     resave: false,
//     saveUninitialized: true
// }
//app.use(session(sessionSettings))
//This function checks for authorisation headers before allowing access
//const protect = async (req, res, next) => {
//     if(!req.headers.authorization) {
//         res.sendStatus(403)
//     } else { 
//         const user = await User.findByPk(req.params.id)
//         res.locals.user = user
//         next()
//     }
// }

//Welcome page
app.get("/", async (req, res) => {
    res.send("Welcome to this page!");
})

app.post('/login', async (req, res) => {
    if (!req.headers.authorization) return res.sendStatus(403)
    const [username, password] = atob(req.headers.authorization.substring(6)).split(":")
    const user = await User.findOne({
        where: {
            username: username
        }
    })
    const isMatch = await bcrypt.compare(password, user.password)
    if (isMatch) {
        fetch('https://dev-ga5nq384.eu.auth0.com/oauth/token', {
            method: 'POST',
            headers: { 
                'content-type': 'application/json' 
            },
            body: '{"client_id":"RKCZVGPvD56Zwuh31ctOAwFFEGCX6yVx","client_secret":"//////","audience":"http://localhost:3000/","grant_type":"client_credentials"}'
        }
        )
        .then(res => res.json())
        .then((result) => {
            console.log(result)
            res.send(result.access_token)
        })
    } else {
    res.sendStatus(403)
}
})

//Displays all users
app.get('/users', async (req, res) => {
    const users = await User.findAll(req.body.users)
    res.send(users)
})

//Displays a user based on ID
app.get('/users/:id', jwtCheck, async (req, res) => {
    const user = await User.findByPk(req.params.id)
    res.send(user)
    //console.log(req.session.id) //consoles out the session ID
    //res.locals.user ? res.send(res.locals.user) : res.sendStatus(404)
})

//Creates a new user and hashes the password
app.post("/users", async (req, res) => {
    const encrypted_password = await bcrypt.hash(req.body.password, 10)
    const user = await User.create({
        username: req.body.username,
        password: encrypted_password
    })
    res.send(user)
})

//Deletes a user based on ID
app.delete('/users/:id', (req, res) => {
    res.sendStatus(200)
})

app.listen(3000, () => {
    sequelize.sync().then(() => console.log("Ready for users"))
})
