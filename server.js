// Importe os módulos necessários
const express = require('express');
const admin = require('firebase-admin');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const serviceAccount = require('./KeyFirebase.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

// Chave secreta para o JWT
const SECRET = 'n7^9Yz$Q@2c8!fAe'

// Rota para criar um novo usuário
app.post('/signup', async (req, res) => {
    try {
        const { email, password, role } = req.body; 
        const userRecord = await admin.auth().createUser({
            email,
            password,
            customClaims: { role: 'user' } 
        });
        
        

        
        await admin.auth().setCustomUserClaims(userRecord.uid, { role });

        res.status(200).json({
            statusCode: 200,
            message: 'Usuário criado com sucesso!',
            data: {
                uid: userRecord.uid,
            },
        });
    } catch (error) {
        console.error('Erro ao criar usuário:', error);
        res.status(500).json({
            statusCode: 500,
            message: 'Erro ao criar usuário.',
        });
    }
});


// Rota para fazer login e obter um token JWT
app.post('/login', async (req, res) => {
    try {
        const { email } = req.body;

        const userRecord = await admin.auth().getUserByEmail(email);

        const userRole = userRecord.customClaims && userRecord.customClaims.role;

        const token = jwt.sign({ uid: userRecord.uid, role: userRole }, SECRET, {
            expiresIn: '2h', // Token expira em 2 horas
        });

        res.status(200).json({
            statusCode: 200,
            message: 'Login realizado com sucesso!',
            data: {
                token,
            },
        });
    } catch (error) {
        console.error('Erro ao fazer login:', error);
        res.status(401).json({
            statusCode: 401,
            message: 'Não autorizado! Usuário não encontrado ou senha incorreta.',
        });
    }
});


// Middleware para verificar o token JWT
const verificarToken = async (req, res, next) => { // Marque a função como async
    const tokenHeader = req.headers['authorization'];
    const token = tokenHeader && tokenHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({
            statusCode: 401,
            message: 'Não autorizado! Token não fornecido.',
        });
    }

    try {
        const decodedToken = jwt.verify(token, SECRET);
        const userRecord = await admin.auth().getUser(decodedToken.uid);
        req.uid = decodedToken.uid;
        req.userRole = userRecord.customClaims && userRecord.customClaims.role;
        next();
    } catch (error) {
        console.error('Erro ao verificar o token:', error);
        res.status(401).json({
            statusCode: 401,
            message: 'Não autorizado! Token inválido.',
        });
    }
    
};


const verificarAdmin = (req, res, next) => {
    if (req.userRole === 'admin') {
        next();
    } else {
        res.status(403).json({
            statusCode: 403,
            message: 'Acesso negado! Esta rota é apenas para administradores.',
        });
    }
};



app.get('/rotaApenasAdmin', verificarToken, verificarAdmin, (req, res) => {
    // Apenas administradores podem acessar esta rota
    res.status(200).json({
        statusCode: 200,
        message: 'Você acessou a rota protegida para administradores.',
    });
});


// Rota protegida que requer token JWT
app.get('/rotaAutenticada', verificarToken, (req, res) => {
    res.status(200).json({
        statusCode: 200,
        message: 'Rota protegida: acesso permitido!',
        data: {
            uid: req.uid,
        },
    });
});

// Servidor na porta 3000
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Listening on port ${PORT}.`);
});
