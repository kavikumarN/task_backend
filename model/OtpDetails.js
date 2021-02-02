const mongoose = require('mongoose');
const Schema =  mongoose.Schema;
mongoose.set('useFindAndModify', false);

// create the user schema
const OtpSchema = new Schema({
    phone:{
        type: String,
        required: false
    },
    onetimepassword:{
        type: String,
        required: false
    },
    date:{
        type: Date,
        required: false
    }
});

module.exports = OTPDetails = mongoose.model('otpDetail',OtpSchema);