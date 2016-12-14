
var mongoose = require('mongoose');

module.exports = mongoose.model('User',{
	//id: String,
	username: String,
	phone: String,
    email: String,

	local            : {
        password     : String,
    },
    google           : {
        id           : String,
        token        : String,
    }

});