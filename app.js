const express = require('express')

const app = express()

app.get('/', (req, res, next) => {
    res.sendFile('/Users/sahajadlakha/Documents/DEV_ZONE/PhishingDetection/UI/index.html')
})

app.get('/checkurl',(req, res, next) => {

    // Running python script
    var spawnSync = require("child_process").spawnSync

    var process = spawnSync('python3',["./app.py", req.query.inputurl])
    var er = process.stderr.toString()

    if (er) {
        console.log(er)
    }

    result = process.stdout.toString().trim()
    console.log(result)
    if (result == "1") {
        res.sendFile('/Users/sahajadlakha/Documents/DEV_ZONE/PhishingDetection/UI/phishy.html')
    } else if (result == "0") {
        res.sendFile('/Users/sahajadlakha/Documents/DEV_ZONE/PhishingDetection/UI/legit.html')
    } else {
        console.log('Error in result from Python script')
    }

})

app.listen(3000, () => {
    console.log("Server listening to http://localhost:3000/")
})