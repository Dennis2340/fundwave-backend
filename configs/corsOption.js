import allowedOrigins from "./allowedOrigin.js"

const corsOption = {
    origin: (origin, callback) => {
        if(allowedOrigins.indexOf(origin) !== -1 || !origin){
            callback(null, true)
        }
        else{
            callback(new Error("not allowed by Cors"))
        }
    },
     optionSuccessStatus: 200
}

export default  corsOption