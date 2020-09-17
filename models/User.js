const mongoose = require('mongoose');
const { isEmail } = require('validator');
const bcrytp = require('bcrypt');

const userSchema = new mongoose.Schema({
    email: {
        type: String,
        unique: [true],
        required: [true, 'Please, enter the email'],
        lowercase: true,
        validate: [isEmail, 'Please, enter a valid email']
    },
    password: {
        type: String,
        required: [true, 'Please, enter the password'],
        minlength: [6, 'Minimum password length is 6 characters']
    },
});

// fire a function before doc was saved
userSchema.pre('save', async function(next) {
    const salt = await bcrytp.genSalt();
    this.password = await bcrytp.hash(this.password, salt);

    next();
})

// static method to login user
userSchema.statics.login = async function(email, password) {
    const user = await this.findOne({ email });
    if (user) {
        const auth = await bcrytp.compare(password, user.password);
        if(auth) {
            return user;
        }
        throw Error('incorrect password');
    } 
    throw Error('incorrect email');
}

const User = mongoose.model('user', userSchema);
module.exports = User;