import { Schema, model } from 'mongoose';
import validator from 'validator';
import bcrypt from 'bcryptjs';

const userSchema = new Schema({
    name: { type: String, required: [true, 'A User must have a Name'], trim: true },
    profileImage: {
        type: String
    },
    email: {
        type: String,
        required: [true, 'A User must have a Profile Image'],
        trim: true,
        unique: true,
        lowercase: true,
        validate: [validator.isEmail, 'Please Provide a valid email']
    },
    password: {
        type: String,
        required: [true, 'Please Provide a password'],
        minlength: 8,
        select: false
    },
    role: {
        type: String,
        enum: ['Admin', 'Manager', 'Staff'],
        default: 'Staff'
    },
    passwordChangedAt: Date
});

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();

    this.password = await bcrypt.hash(this.password, 12);
    next();
});

userSchema.pre('save', function (next) {
    if (!this.isModified('password') || this.isNew) return next();

    this.passwordChangedAt = Date.now() - 1000;
    next();
});

userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
    return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);

        return JWTTimestamp < changedTimestamp;
    }

    // False means NOT changed
    return false;
};

const User = new model('User', userSchema);

export default User;
