const express = require('express')

const app = express()

app.get('/', (req, res, next) => {
    res.sendFile('/Users/sahajadlakha/Documents/DEV_ZONE/PhishingDetection/UI/index.html')
})

app.get('/checkurl',(req, res, next) => {
    var spawn = require("child_process").spawn

    var process = spawn('python',["./test.py", req.query.inputurl])

    process.stdout.on('data', (data) => {
        console.log(data)
        console.log(data.toString())
        res.send(data.toString())
    })
})

app.listen(3000, () => {
    console.log("Server listening to http://localhost:3000/")
})