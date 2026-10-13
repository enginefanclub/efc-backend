const { Server } = require("socket.io")
const crypto = require('crypto')

let sprites = []

const io = new Server({
    cors: {
        origin: "*"
    }
})

const sha512 = (str) => crypto.createHash('sha512').update(str).digest('hex');

const disconnectGrace = new Map();

io.on("connection", (socket) => {
    const ip = (socket.handshake.auth && socket.handshake.auth.token) || "0";
    socket.emit('reconnect', sprites.filter(x => x.ip != ip));

    clearTimeout(disconnectGrace.get(ip))
    disconnectGrace.delete(ip)

    socket.on('addsprite', (id) => {
        let ipData = sprites.find(x => x.ip == ip);
        if (ipData) {
            ipData.connected = true;
            return;
        }
        console.log(`[${ip}] Add new critter`, id);
        socket.broadcast.emit('addsprite', ip, id)
        sprites.push({ ip, id, connected: true })
    })
    socket.on('delsprite', () => {
        let ipData = sprites.find(x => x.ip == ip);
        if (ipData) {
            console.log(`[${ip}] Delete critter`, ipData.id);
            socket.broadcast.emit('delsprite', ip)
            sprites.splice(sprites.indexOf(ipData), 1)
        }
    })
    socket.on('changesprite', (id) => {
        let ipData = sprites.find(x => x.ip == ip);
        if (ipData) {
            console.log(`[${ip}] Change sprite from ${ipData.id} to ${id}`);
            socket.broadcast.emit('changesprite', ip, id, ipData.id)
            ipData.id = newid;
        }
    })
    socket.on('disconnect', () => {
        let ipData = sprites.find(x => x.ip == ip);
        if (ipData) {
            ipData.connected = false;
            disconnectGrace.set(ip, setTimeout(function() {
                let ipData2 = sprites.find(x => x.ip == ip);
                if (ipData2) {
                    if (!ipData2.connected) {
                        console.log(`[${ip}] [Disconnect] Delete critter`, ipData.id);
                        socket.broadcast.emit('delsprite', ip)
                        sprites.splice(sprites.indexOf(ipData), 1)
                    }
                }
            }, 10000))
        }
    })
})

io.listen(3000)
console.log("Listening on port 3000!");