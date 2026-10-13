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
    const ip = sha512(socket.request.connection.remoteAddress);
    socket.emit('reconnect', sprites.map(x => x.id));

    clearTimeout(disconnectGrace.get(ip))
    disconnectGrace.delete(ip)

    socket.on('addsprite', (id) => {
        let ipData = sprites.find(x => x.ip == ipAddr);
        if (ipData) {
            ipData.connected = true;
            return;
        }
        console.log("Add new critter", id);
        socket.broadcast.emit('addsprite', id)
        sprites.push({ ip, id, connected: true })
    })
    socket.on('delsprite', () => {
        let ipData = sprites.find(x => x.ip == ipAddr);
        if (ipData) {
            console.log("Delete critter", ipData.id);
            socket.broadcast.emit('delsprite', ipData.id)
            sprites.splice(sprites.indexOf(ipData), 1)
        }
    })
    socket.on('changesprite', (id) => {
        let ipData = sprites.find(x => x.ip == ipAddr);
        if (ipData) {
            console.log(`Change sprite from ${ipData.id} to ${id}`);
            socket.broadcast.emit('changesprite', id, ipData.id)
            ipData.id = newid;
        }
    })
    socket.on('disconnect', () => {
        let ipData = sprites.find(x => x.ip == ipAddr);
        if (ipData) {
            ipData.connected = false;
            disconnectGrace.set(ip, setTimeout(function() {
                let ipData2 = sprites.find(x => x.ip == ipAddr);
                if (ipData2) {
                    if (!ipData2.connected) {
                        console.log("[Disconnect] Delete critter", ipData.id);
                        socket.broadcast.emit('delsprite', ipData.id)
                        sprites.splice(sprites.indexOf(ipData), 1)
                    }
                }
            }, 10000))
        }
    })
})

io.listen(3000)
console.log("Listening on port 3000!");