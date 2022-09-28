const User = require('../models/userModel');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');



const filterObj = (obj, ...expectedFields) => {
    let newObj = {};
    // loop through the keys of the body object, if the expected fields object contains
    // any of the keys, add it to the new Obj.
    Object.keys(obj).forEach(el => {
        if(expectedFields.includes(el)) newObj[el] = obj[el]
    })
    return newObj
}

exports.getAllUsers = catchAsync(async () => {
    const users = await User.find();

    res.status(200).json({
        status: 'success',
        results: users.length,
        data: {
            users
        }
    })
}) 

exports.updateMe = catchAsync( async () => {
    // Create error if user POSTS password data
    if(req.body.password || req.body.confirmPassword){
        return next(new AppError('This route is not for updating password'))
    }

    // Update user document
    // Filter out fields that are not supposed to be in the body
    const filteredBody = filterObj(req.body, 'username', 'email');
    const updatedUser = User.findByIdAndUpdate(req.user.id, filteredBody, {
        new: true,
        runValidators: true
    })

    res.status(200).json({
        status: 'success',
        data: {
            user: updatedUser
        }
    })
})

exports.deleteMe = catchAsync(async (req, res, next) => {
    await User.findByIdAndUpdate(req.user.id, {active: false})

    res.status(204).json({
        status: 'success',
        data: null
    })
})