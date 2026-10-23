const http = require("http")
const express = require('express')

const app = express();
const server = http.createServer(app)
const { Server } = require("socket.io")
const crypto = require('crypto')

const Database = require('better-sqlite3');

const bcrypt = require('bcrypt')

let db = new Database(require("path").resolve("./data/database.sqlite"), {
    verbose: console.log
});

const { RegExpMatcher, TextCensor, englishDataset, englishRecommendedTransformers } = require('obscenity');
const matcher = new RegExpMatcher({
	...englishDataset.build(),
	...englishRecommendedTransformers,
});

function println(str) {
    console.log(str);
}

/*
CREATE TABLE "users" (
	"user_id"	INTEGER NOT NULL DEFAULT 0,
	"username"	TEXT NOT NULL DEFAULT 'User',
	"password"	TEXT NOT NULL,
	"salt"	TEXT NOT NULL,
	"joined"	BLOB DEFAULT 0,
	"lastOnline"	INTEGER DEFAULT 0,
	"icon"	TEXT DEFAULT 'user',
	"badges"	TEXT DEFAULT '[]',
	"badgeColor"	TEXT DEFAULT '#000000',
	"trophies"	TEXT DEFAULT '[]',
	"critters"	TEXT DEFAULT '[''cat'']',
	"token"	TEXT,
	"critter_selected"	TEXT DEFAULT 'cat',
	"exclusive_icons"	TEXT DEFAULT '[]',
	PRIMARY KEY("user_id")
);
*/

let critters = {};
let badges = {};
let icons = {};
let trophies = {};

const validator = require('express-validator');

let sprites = []

const io = new Server(server, {
    cors: {
        origin: "*"
    }
})

// verity stuff

function validateUsername(username) {
    if (username.length < USERNAME_LENGTH_MIN) return "Please enter in a username that is longer than 2 characters!";
    if (username.length > USERNAME_LENGTH_MAX) return "Please enter in a username that is less than than 20 characters!";
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return "Usernames cannot contain any special characters! They can only contain letters, numbers, and an underscore.";
    if (matcher.hasMatch(username.trim())) return "Profanity is not allowed in usernames!";
    if (["login","register"].includes(username.toLowerCase().trim())) return "illegal";
    return null;
}

function verifyToken(token) {
    return new Promise((resolve, reject) => {
        const userData = db.prepare('SELECT user_id, username, joined, lastOnline, icon, badges, badgeColor, trophies, critters, critter_selected, exclusive_icons FROM users WHERE token = ?').get(token);
        if (!userData) return reject("Invalid token");
        resolve(userData);
    })
}

app.set('trust proxy', 1);
app.use(require('cors')({
    origin: true
}))
app.use(express.urlencoded({
    extended: false,
    limit: '50mb'
}));
app.use(
    express.json({
        limit: '50mb',
        verify: (_, res, buf, __) => {
            try {
                JSON.parse(buf);
            } catch (e) {
                res.statusCode(403).send("no.");
                throw Error('invalid JSON');
            }
        }
    })
)

app.use((req, res, next) => {
    if (!req.headers['authorization']) return next();
    verifyToken(req.headers['authorization']).then(user => {
        req.user = user;
        next();
    }).catch(err => {
        console.error(err);
        res.sendStatus(401);
    })
})
app.post('/verify', (req, res) => {
    if (!req.headers['authorization']) return res.sendStatus(401);
    if (req.user) return res.sendStatus(200);
    res.sendStatus(401);
})

function makeID(length) {
    let result = '';
    let chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    let dateNow = Date.now().toString();

    let finalfinal = dateNow.slice(Math.ceil(dateNow.length / 2)) + result + dateNow.slice(0, Math.ceil(dateNow.length / 2)) + Math.random().toString();
    let splitFinal = finalfinal.split("");
    for (let i = 0; i < finalfinal.length; i++) {
        let chr = splitFinal[i];
        if (!isNaN(parseInt(chr))) {
            splitFinal[i] = chars[parseInt(chr)]
        }
    }

    return splitFinal.join("") + "DONOTSHARE"
}
function createToken(user_id, res) {
    const token = makeID(32);
    db.prepare('UPDATE users SET token = ? WHERE user_id = ?').run(token, user_id);
    return res.json({ user_id, token });
}

const USERNAME_LENGTH_MIN = 3;
const USERNAME_LENGTH_MAX = 20;
const PASSWORD_LENGTH_MIN = 6;
const PASSWORD_LENGTH_MAX = 512;

app.post('/auth', (req, res) => {
    if (req.user) return res.sendStatus(204);
    const { username, password } = req.body;
    if ([username, password].includes(undefined)) return res.status(406).send('Missing username or password');
    const userData = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    if (!userData) return res.status(404).send('Invalid username or password');
    return bcrypt.compare(`${userData.salt}.${password}`, userData.password, function (err, result) {
        if (err) return res.status(500).send('An error occurred while comparing the password');
        if (!result) return res.status(401).send('Invalid username or password');

        return createToken(userData.user_id, res);
    });
})
app.post('/register', (req, res) => {
    if (req.user) return res.sendStatus(204);
    const { username, password } = req.body;
    if ([username, password].includes(undefined)) return res.status(406).send('Missing username and/or password');
    let userNameRes = validateUsername(username);
    if (userNameRes != null) return res.status(406).send(userNameRes);
    if (password.length < PASSWORD_LENGTH_MIN) return res.status(406).send("Please enter in a password that is longer than 6 characters!");
    if (password.length > PASSWORD_LENGTH_MAX) return res.status(406).send("calm down");
    const userData = db.prepare('SELECT count(*) FROM users WHERE username = ?').pluck().get(username);
    if (userData) return res.status(409).send('Someone with that username already exists!');
    const userSalt = crypto.randomBytes(32);
    return bcrypt.hash(`${userSalt.toString('hex')}.${password}`, 10, function (err, hash) {
        if (err) return res.status(500).send("An error occured while trying to hash the password.");
        const timestamp = Date.now()
        db.prepare('INSERT INTO users (username, salt, password, joined, lastOnline) VALUES (?, ?, ?, ?, ?)')
            .run(username, userSalt.toString('hex'), hash, timestamp, timestamp);
        const newUserData = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (!newUserData) return res.status(500).send("An error occured while trying to get the user after creating it.");
        console.log(`new user registered: ${username}`);
        return createToken(newUserData.user_id, res);
    })
})
app.post("/settings/username", validator.body('username').notEmpty().isString(), (req, res) => {
    if (!req.user) return res.sendStatus(401);
    const result = validator.validationResult(req);
    if (!result.isEmpty()) return res.status(400).json({ errors: result.array() })
    const { username } = req.body;
    let userNameRes = validateUsername(username);
    if (userNameRes != null) return res.status(406).send(userNameRes);
    const userExists = db.prepare('SELECT count(*) FROM users WHERE username = ?').pluck().get(username);
    if (userExists) return res.status(409).send('Someone with that username already exists!');
    db.prepare('UPDATE users SET username = ? WHERE user_id = ?').run(username, req.user.user_id);
    return res.sendStatus(200);
})
app.post("/settings/password", validator.body('password').notEmpty().isString(), (req, res) => {
    if (!req.user) return res.sendStatus(401);
    const result = validator.validationResult(req);
    if (!result.isEmpty()) return res.status(400).json({ errors: result.array() })
    const { password } = req.body;
    if (password.length < 8) return res.status(406).send("Please enter in a password that is longer than 8 characters!");
    if (password.length > 1024) return res.status(406).send("calm down");
    return bcrypt.hash(`${userData.salt}.${password}`, 10, function(err, hash) {
        if (err) return res.status(500).send("An error occured while trying to hash the password.");
        db.prepare('UPDATE users SET password = ? WHERE user_id = ?').run(hash, req.user.user_id);
        res.sendStatus(200);
    })
})
app.post("/settings/icon", validator.body('icon').notEmpty().isString(), async (req, res) => {
    if (!req.user) return res.sendStatus(401);
    const result = validator.validationResult(req);
    if (!result.isEmpty()) return res.status(400).json({ errors: result.array() })
    const { icon } = req.body;
    let realIcon = icons[icon];
    if (realIcon) {
        let exclusive = [];
        try {
            exclusive = JSON.parse(req.user.exclusive_icons);
        } catch(_) {}
        if (!realIcon.default && !exclusive.includes(icon)) {
            return res.status(400).send("YOU THINK YOU HAVE THE RIGHT TO USE SUCH GLORY AS THIS!?!?! KNOW YOUR PLACE PEASANT!!!")
        }
        db.prepare('UPDATE users SET icon = ? WHERE user_id = ?').run(icon, req.user.user_id);
        res.sendStatus(200);
    } else {
        res.status(400).send("i am a fat CAR!")
    }
})
app.post("/settings/colour", validator.body('colour').notEmpty().isString(), async (req, res) => {
    if (!req.user) return res.sendStatus(401);
    const result = validator.validationResult(req);
    if (!result.isEmpty()) return res.status(400).json({ errors: result.array() })
    const { colour } = req.body;

    const hexColor = /^#[A-Fa-f0-9]{6}$/;
    if (!hexColor.test(colour) && value != "#0") return res.status(400).send("BAD COLOUR!");
    db.prepare('UPDATE users SET badgeColor = ? WHERE user_id = ?').run(colour, req.user.user_id);
    res.sendStatus(200);
})

app.get("/myself", (req, res) => {
    if (!req.user) return res.sendStatus(401);
    return res.json(req.user)
})

app.get("/users/:username", (req, res) => {
    const userData = db.prepare('SELECT user_id, username, joined, lastOnline, icon, badges, badgeColor, trophies, critter_selected FROM users WHERE username = ?').get(req.params.username);
    if (!userData) return res.sendStatus(404);
    return res.json(userData)
})

app.post("/users/:user/give", validator.body('key').notEmpty().isString(), validator.body('value').notEmpty().isString(), (req, res) => {
    if (!req.user) return res.sendStatus(401);
    let myUserBadges = req.user.badges;
    try {
        myUserBadges = JSON.parse(req.user.badges);
    } catch (e) {
        return res.status(500).send("what.")
    }
    if (!myUserBadges.includes("admin")) return res.sendStatus(403);
    const result = validator.validationResult(req);
    if (!result.isEmpty()) return res.status(400).json({ errors: result.array() })
    const userData = db.prepare('SELECT * FROM users WHERE user_id = ?').get(req.params.user);
    if (!userData) return res.sendStatus(404);
    const { key, value } = req.body;
    switch (key) {
        case "icon": {
            let realIcon = icons[value];
            if (!realIcon) return res.status(400).send("i am a fat CAR!");
            if (realIcon.default) return res.status(400).send("thats a default icon, silly!");
            let userIcons = userData.exclusive_icons;
            try {
                userIcons = JSON.parse(userData.exclusive_icons);
            } catch (e) {
                return res.status(500).send("please contact firee because the json didnt parse right, heres their json: " + userIcons)
            }
            if (userIcons.includes(value)) return res.status(400).send("they already own that icon!");
            userIcons.push(value);
            db.prepare('UPDATE users SET exclusive_icons = ? WHERE user_id = ?').run(JSON.stringify(userIcons), userData.user_id);
            res.sendStatus(200);
            break;
        }
        case "badge": {
            let realBadge = badges[value];
            if (!realBadge) return res.status(400).send("i am a fat CAR!");
            let userBadges = userData.badges;
            try {
                userBadges = JSON.parse(userData.badges);
            } catch (e) {
                return res.status(500).send("please contact firee because the json didnt parse right, heres their json: " + userBadges)
            }
            if (userBadges.includes(value)) return res.status(400).send("they already own that badge!");
            userBadges.push(value);
            db.prepare('UPDATE users SET badges = ? WHERE user_id = ?').run(JSON.stringify(userBadges), userData.user_id);
            res.sendStatus(200);
            break;
        }
        case "critter": {
            let realCritter = critters[value];
            if (!realCritter) return res.status(400).send("i am a fat CAR!");
            let userCritters = userData.critters;
            try {
                userCritters = JSON.parse(userData.critters);
            } catch (e) {
                return res.status(500).send("please contact firee because the json didnt parse right, heres their json: " + userCritters)
            }
            if (userCritters.includes(value)) return res.status(400).send("they already own that critter!");
            userCritters.push(value);
            db.prepare('UPDATE users SET critters = ? WHERE user_id = ?').run(JSON.stringify(userCritters), userData.user_id);
            res.sendStatus(200);
            break;
        }
        default:
            return res.status(400).send("Invalid key");
    }
})

app.get("/users", (req, res) => {
    let page = parseInt(req.query.page) || 0
    if (isNaN(page) || page < 0) page = 0;
    return res.json({users: db.prepare('SELECT user_id, username, joined, lastOnline, icon, badges, badgeColor, trophies, critter_selected FROM users ORDER BY joined DESC LIMIT 20 OFFSET ?').all((20 * page)), count: db.prepare('SELECT count(*) FROM users').pluck().get()})
})


// verify stuff

const sha512 = (str) => crypto.createHash('sha512').update(str).digest('hex');

const disconnectGrace = new Map();

io.on("connection", async (socket) => {
    const token = (socket.handshake.auth && socket.handshake.auth.token) || "0";
    const ip = (socket.handshake.auth && socket.handshake.auth.id) || "0";

    let userData = null;
    if (token.length > 25) {
        try {
            userData = await verifyToken(token)
        } catch (e) { }
    }

    socket.emit('reconnect', sprites.filter(x => x.ip != ip));

    if (userData == null) {
        socket.emit('youarespectator')
    }

    if (token == "0" && ip == "0") return;

    clearTimeout(disconnectGrace.get(ip))
    disconnectGrace.delete(ip)

    socket.on('addsprite', () => {
        let ipData = sprites.find(x => x.ip == ip);
        if (ipData) {
            ipData.connected = true;
            return;
        }
        if (userData) {
            console.log(`[${ip}] Add new critter`, userData.critter_selected);
            socket.broadcast.emit('addsprite', ip, userData.critter_selected, userData.username)
            sprites.push({ ip, id: userData.critter_selected, username: userData.username, connected: true })
        } else {
            socket.broadcast.emit('addspectator', ip)
            sprites.push({ ip, id: null, connected: true })
        }
    })
    socket.on('delsprite', () => {
        let ipData = sprites.find(x => x.ip == ip);
        if (ipData) {
            if (userData) {
                console.log(`[${ip}] Delete critter`, ipData.id);
                socket.broadcast.emit('delsprite', ip)
            } else {
                socket.broadcast.emit('delspectator', ip)
            }
            sprites.splice(sprites.indexOf(ipData), 1)
        }
    })
    socket.on('changesprite', (id) => {
        let ipData = sprites.find(x => x.ip == ip);
        if (ipData) {
            if (userData) {
                try {
                    let critters = JSON.parse(userData.critters);
                    if (!critters.includes(id)) return;
                    db.prepare('UPDATE users SET critter_selected = ? WHERE user_id = ?').run(id, userData.user_id);
                    console.log(`[${ip}] Change sprite from ${ipData.id} to ${id}`);
                    socket.broadcast.emit('changesprite', ip, id, ipData.id, userData.username)
                    ipData.id = id;
                } catch (e) {
                    console.error(`[${ip}] Couldn't change sprite, JSON invalid?`)
                }
            }
        }
    })
    socket.on('disconnect', () => {
        let ipData = sprites.find(x => x.ip == ip);
        if (ipData) {
            ipData.connected = false;
            disconnectGrace.set(ip, setTimeout(function () {
                let ipData2 = sprites.find(x => x.ip == ip);
                if (ipData2) {
                    if (!ipData2.connected) {
                        if (userData) {
                            db.prepare('UPDATE users SET lastOnline = ? WHERE user_id = ?').run(Date.now(), userData.user_id)
                            console.log(`[${ip}] [Disconnect] Delete critter`, ipData.id);
                            socket.broadcast.emit('delsprite', ip)
                        } else {
                            console.log(`[${ip}] [Disconnect] Delete spectator`);
                            socket.broadcast.emit('delspectator', ip)
                        }
                        sprites.splice(sprites.indexOf(ipData), 1)
                    }
                }
            }, 10000))
        }
    })
})

app.all('/', (_, res) => {
    res.redirect("https://engine.nefarkitti.dev");
})

server.listen(3000, async () => {
    console.log("Listening on port 3000!");
    try {
        critters = await (await fetch("https://efc.nefarkitti.dev/assets/jsons/critters.json")).json();
        badges = await (await fetch("https://efc.nefarkitti.dev/assets/jsons/profile/badges.json")).json();
        icons = await (await fetch("https://efc.nefarkitti.dev/assets/jsons/profile/icons.json")).json();
        trophies = await (await fetch("https://efc.nefarkitti.dev/assets/jsons/profile/trophies.json")).json();
    } catch (e) {
        console.log("Couldn't get some URLS!");
        console.error(e)
    }
});