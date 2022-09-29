const User = require('../models/userModel');
const jwt = require('jsonwebtoken');
const catchAsync  = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const sendEmail = require('./email');


const signJWT = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN
    })
}

const createSendToken = (user, statusCode, res) => {
    const token = signJWT(user._id)
    // create a cookie options object to send the jwt with a cookie
    const cookieOptions = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000),
        httpOnly: true
    }
    // If in production, send cookie over a secure http (https)
    if(process.env.NODE_ENV === 'production'){
        cookieOptions.secure = true
    }

    res.cookie('jwt', token, cookieOptions)

    res.status(statusCode).json({
        status: 'success',
        data: {
            username: user.username,
            inSession: true
        }
    })
}

exports.signup = catchAsync(async (req, res, next) => {
    const newUser = await User.create({
        username: req.body.username,
        email: req.body.email,
        password: req.body.password,
        passwordConfirm: req.body.confirmPassword
    })
    createSendToken(newUser, 201, res)
})




exports.login = async (req, res, next) => {
    // Check if email & password exist in the req.body
    const {email, password} = req.body;
    if(!email || !password){
        return next(new AppError('Please enter your email and password', 400))
        // return res.status(400).json({
        //     status: 400,
        //     message: 'Please enter your email and password'
        // })
    }
    // Check if the user exists and if the password is correct
    const user = await User.findOne({email}).select('+password')
    if(!user || !(await user.correctPassword(password, user.password))){
        return next(new AppError('Invalid email or password', 401))
        // return res.status(401).json({
        //     status: 401,
        //     message: 'Invalid email or password'
        // })
    }
    createSendToken(user, 200, res)
}

exports.protect = catchAsync( async (req, res, next) => {
    // 1) Getting token and check if it exist
    let token;
    if(req.headers.authorization && req.headers.authorization.startsWith('Bearer')){
        token = req.headers.authorization.split(' ')[1];
    }

    if(!token){
        return next(new AppError('You are not logged in!. PLease log in to get access', 401))
    }

    // 2) Validate the token (Verification)
    // takes in a callback, but we can use node built in promisify function. 
    // so we can await the result of the verification and store the result
    // This below is a curried function
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET)
    // USing callbacks
    // let decoded;
    // jwt.verify(token, process.env.JWT_SECRET, (err, value) => {
    //     decoded = value
    // })
    // 3) Check if user still exists
    const currentUser = await User.findById(decoded.id);
    if(!currentUser){
        return next(new AppError('The user belonging to the token no longer exists', 401))
    }
    // 4) Check if the user changed passwords after the jwt was issued
    if(currentUser.changedPasswordAfter(decoded.iat)){
        return next(new AppError('User recently changed password. Please log in again', 401))
    }
    // Grant access to protected route
    req.user = currentUser
    next()
})

exports.forgotPassword = catchAsync(async (req, res, next) => {
    // Get user based on posted email
    const user = await User.findOne({email: req.body.email})
    if(!user){
        next(new AppError('There is no user with given email address', 404))
    }
    //  Generate the random token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false});

    // Send it back as an email
    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`

    const message = `Forgot your password ? Click the provided link to reset
    your password.This link expires after 10 minutes.If you didn't forget your password, please ignore,
    this email`;

    try {
        await sendEmail({
            email: user.email,
            subject: 'Password Reset',
            message
        })

        res.status(200).json({
            status: 'success',
            message: 'Password reset link sent to email'
        })
    } catch (error) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });

        return next(new AppError('There was an error sending the email. Try again later', 500))
    }

})

exports.resetPassword = catchAsync(async (req, res, next) => {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex')

    const user = await User.findOne({
        passwordResetToken: hashedToken,
        passwordResetExpires: {$gt: Date.now()}
    });

    // If the token has not expired and there is a user, set the new password
    if(!user) return next(new AppError('Token is invalid or has expired', 400))

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;

    await user.save()
    // 3) Update changedPasswordAt property for the user
    // 4) Log the user in, send JWT
    createSendToken(user, 200, res)
})

exports.updatePassword = catchAsync (async (req, res, next) => {
    // 1) Get the user from the collection
    const user = await User.findById(req.user.id).select('+password');
    // 2) Check if the Posted password is correct
    if(!user.correctPassword(req.body.oldpassword, user.password)){
        return next(new AppError('Your current password is wrong', 401))
    }
    // 3) If so, update password
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    await user.save();
    // 4) Log user in, send jwt\
    createSendToken(user, 200, res)
})