const { Router } = require('express');
const router = Router();

const jwt = require('jsonwebtoken');
const config = require('../config');
const verifyToken = require('./verifyToken');

const User = require('../models/User');

router.post('/signup', async (req, res, next) => {
    const { username, email, password } = req.body;
    const user = new User({
        username,
        email,
        password
    });

    user.password = await user.encryptPassword(user.password);
    await user.save();

    const token = jwt.sign({id: user._id}, config.secret, {
        expiresIn: 60 * 60 * 24
    });

    res.json({auth: true, token});
});

router.get('/me', verifyToken, async (req, res, next) => {
    
    const user = await User.findById(req.userId, { password: 0 });

    if (!user) {
        return res.status(404).send('No user found');
    }
    
    res.json(user);
});

router.post('/signin', async (req, res, next) => {
    const { email, password } = req.body;
    const user = await User.findOne({email});
    if (!user) {
        return res.status(404).send("The email doesn't exists");
    }

    const validPassword = await user.validatePassword(password);
    if (!validPassword) {
        res.status(401).json({auth: false, token: null});
    }

    const token = jwt.sign({id: user._id}, config.secret, {
        expiresIn: 60 * 60 * 24
    });

    res.json({auth: true, token});
});


module.exports = router;