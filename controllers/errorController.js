const AppError = require("../utils/appError");
const mongoose = require('mongoose');

const handleCastErrorDB = err => {
    const message = `Invalid ${err.path}: ${err.value}`
    return new AppError(message, 400)
}

const handleDuplicateFieldsDB = err => {
    const value = err.message.match(/(["'])(?:(?=(\\?))\2.)*?\1/)[0]
    // const message = `Duplicate field value: ${value}. PLease use another value!`
    const message = `Email already exists`
    return new AppError(message, 400)
}

const handleValidationErrorDB = err => {
    // To get the message to be sent,
    // 1) Create an empty array (errMsgs)
    // 2) Loop over the errors obj and for each error object in the errors obj, append the message property to the array
    // 3) convert the errMsgs array to a string and assign it to the message.
    
    const errMsgs = Object.values(err.errors).map(el => el.message)
    
    const message = `${errMsgs.join('. ')}`;
    return new AppError(message, 400)
}

const handleJWTError = err => new AppError('Invalid token. Please login again', 401)

const handleJWTExpiredError = err => new AppError('Your token has expired. Please log in again', 401)

const sendErrorDev = (err, res) => {
    res.status(err.statusCode).json({
        status: err.status,
        err: err,
        message: err.message,
        stack: err.stack
    });
}


const sendErrorProd = (err, res) => {
    // Operational, trusted error: send error to client
    if(err.isOperational){
        
        res.status(err.statusCode).json({
            status: err.status,
            message: err.message
        });
    // Programming or other unknown error: don't leak error details
    }else{
        // 1) Log error
        // console.error('Error: ', err)
        // 2) send generic message
        res.status(500).json({
            status: 'error',
            message: 'Something went very wrong'
        })
    }
}

module.exports = (err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';

    if(process.env.NODE_ENV === 'development'){
        sendErrorDev(err, res)
    }else if(process.env.NODE_ENV === 'production'){
        let error = {...err};
        error.message = err.message
        // For casr error .. i.e invalid database id
        if(err instanceof mongoose.Error.CastError){
            error = handleCastErrorDB(error)
        }
        //  for duplicate name error
        if(err.code === 11000){
            error.message = err.message
            error = handleDuplicateFieldsDB(error)
        } 
        if(err instanceof mongoose.Error.ValidationError){
            error = handleValidationErrorDB(error)
        }
        if(error.name === 'JsonWebTokenError'){
            error = handleJWTError(error)
            console.log(error)
        }
        if(error.name === 'TokenExpiredError'){
            error = handleJWTExpiredError(error)
        }
        sendErrorProd(error, res)
    }
}