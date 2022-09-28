const mongoose = require('mongoose');
const dotenv = require('dotenv');

process.on('uncaughtException', err => {
    console.log(err.name, err.message);
    console.log('Uncaught exception.... Shutting down');
    process.exit(1);
})

dotenv.config({path: './config.env'});

const app = require('./app')

const DB = process.env.DATABASE.replace('<password>', process.env.DATABASE_PASSWORD);

mongoose.connect(DB, {
    useNewUrlParser: true,
    useCreateIndex: true,
    useFindAndModify: false,
    useUnifiedTopology: true
}).then(() => console.log('Database connected successfully'))

const port = process.env.PORT || 5000

const server = app.listen(port, () => {
    console.log(`App listening on port ${port} ...`)
})

process.on('unhandledRejection', err => {
    console.log(err.name, err.message);
    console.log('Unhandled Rejection.... Shutting down');
    server.close(() => {
        process.exit(1)
    })
})