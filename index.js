const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const user = require('./model/user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'gdyh#%$HJKHY*FNHEhjhtd8Fhg94hDFDTFJ3w$&(*YGcghjhku8';

mongoose.connect('mongodb://localhost:27017/user-db', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true
});

const app = express();
app.use('/', express.static(path.join(__dirname, 'static')));
app.use(bodyParser.json());

app.post('/api/login', async(req, res) => {

    const { username, password } = req.body;

    const users = await user.findOne({ username }).lean();

    if(!users){
        return res.json({ status: 'error', error: 'Invalid username/ password!' });
    }
    
    if(await bcrypt.compare(password, users.password)){

        const token = jwt.sign({ id: users._id, username: users.username }, JWT_SECRET)
        return res.json({ status: 'ok', data: token });
    }

    res.json({ status: 'error', error: 'Invalid username/ password!' });
})

app.post('/api/register', async(req, res) => {

    const { username, email, password: plainTextPassword} = req.body;
    const password = await bcrypt.hash(plainTextPassword, 10);

    if(!username || typeof username !== 'string'){
        return res.json({ status: 'error', error: 'Invalid username!' })
    }

    if(!plainTextPassword){
        return res.json({ status: 'error', error: 'Enter a strong password!' })
    }

    if(plainTextPassword.length < 5){
        return res.json({ status: 'error', error: 'Password is too small!' })
    }

    try {
       const response = await user.create({
           username,
           email,
           password
       })
       console.log('User created successfully',response); 
    } catch (error) {
        if(error.code === 11000){
            return res.json({ status: 'error', error: 'Username not available!' })
        }
        throw error;
    }

    res.json({ status: 'ok' });
});

app.post('/api/forgot-password', async(req, res) => {

    const{ token, newPassword: plainTextPassword } = req.body;

    if(!plainTextPassword){
        return res.json({ status: 'error', error: 'Enter a strong password!' })
    }

    if(plainTextPassword.length < 5){
        return res.json({ status: 'error', error: 'Password is too small!' })
    }

    try {

        const users = jwt.verify(token, JWT_SECRET);
        const id = users.id;
        const password = await bcrypt.hash(plainTextPassword, 10);

        await user.updateOne({ id }, 
            {
            $set: { password }
        })
        res.json({ status: 'ok' });
    } catch (error) {
        
        res.json({ status: 'error', error: ';))'})
    }
    
    
})


app.listen(3000, () => {
    console.log('Server up at 3000');
});