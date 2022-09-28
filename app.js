const express = require('express');
const morgan = require('morgan');

const rateLimit = require('express-rate-limit')
const helmet = require('helmet')
const mongoSanitize = require('express-mongo-sanitize')
const xss = require('xss-clean')
const hpp = require('hpp')
const cors = require('cors')

const globalErrorHandler = require('./controllers/errorController')

const userRouter = require('./routes/userRoute');
const AppError = require('./utils/appError');

const app = express();

// app.use(cors());

const corsConfig = {
    origin: true,
    credentials: true,
};
app.set("trust proxy", 1)
app.use(cors(corsConfig))
app.options('*', cors(corsConfig));

app.use(helmet())

if(process.env.NODE_ENV === 'development'){
    app.use(morgan('dev'))
}

// limit request from same api
const limiter = rateLimit({
    max: 100,
    windowMs: 60 * 60 * 1000,
    message: 'Too many requests from this IP, please try again in an hour'
});

app.use('/api', limiter)

// Body parser, reading data from body into req.body
app.use(express.json({
    limit: '10kb'
}))

// Data sanitization against nosql query injection 
app.use(mongoSanitize());

// Data sanitization against XSS (Cross site scripting attacks)
app.use(xss())

// Prevent parameter pollution
app.use(hpp({
    whitelist: [ 'duration', 'ratingsQuantity', 'ratingsAverage', 'maxGroupSize', 'difficulty', 'price' ]
}))

// Routers
app.use('/api/v1/users', userRouter)

app.use('*', (req, res, next) => {
    next(new AppError(`Can't find ${req.originalUrl} on this server`, 404))
})
app.use(globalErrorHandler)

module.exports = app;