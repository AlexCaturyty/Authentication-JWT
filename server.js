const express = require('express');
const app = express();

const admin = require('firebase-admin');
const credentials = require('./KeyFirebase.json');

admin.initializeApp({
    credential: admin.credential.cert(credentials)
});

app.use(express.json());

app.use(express.urlencoded({ extended:true }));

app.post('/signup', async (req, res) => {
    console.log(req.body);
    const user={
        email: req.body.email,
        password: req.body.password
    }
    const userResponse = await admin.auth().createUser({
    email: user.email,
    password: user.password,
    emailVerified: false,
    disabled: false    
    })
    res.json(userResponse);
});



const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`flistening on port ${PORT}.`);
});