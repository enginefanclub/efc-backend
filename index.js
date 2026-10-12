const { Server } = require("socket.io")

let sprites = []

const io = new Server({
    cors: {
        origin: "*"
    }
})

io.on("connection", (socket) => {
    socket.emit('reconnect', sprites);

    socket.on('addsprite', (id)=> {
        socket.broadcast.emit('addsprite', id)
        sprites.push(id)
    })
    socket.on('delsprite', (id)=>{
        socket.broadcast.emit('delsprite', id)
        sprites.splice(sprites.indexOf(id), 1)
    })
    socket.on('disconnect', (id)=>{
        socket.broadcast.emit('delsprite', id)
        sprites.splice(sprites.indexOf(id), 1)
    })
})

io.listen(3000)