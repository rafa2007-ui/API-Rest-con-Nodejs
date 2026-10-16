import { MongoClient, ObjectId } from 'mongodb' // Documentación CRUD: https://mongodb.github.io/node-mongodb-native/6.2/
import express from "express";
import cors from "cors";
import bcrypt from 'bcryptjs';
import jwt from "jsonwebtoken";
import swaggerUi from "swagger-ui-express"
import swaggerDocument from "./openapi.json" with { type: "json" }
import rateLimit from 'express-rate-limit';

const app = express()
app.use(express.json())  // IMPORTANTE: SOPORTE PARA JSON
app.use(cors())          // Para habilitar CORS 
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

const loginLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minuto
    limit: 5,             // Máximo 5 peticiones
    message: {
        message: 'Demasiados intentos. Inténtalo más tarde.'
    },
    standardHeaders: true,
    legacyHeaders: false
});

const PORT = process.env.PORT ?? 3000
const DB_URL = process.env.MONGODB_URI ?? 'mongodb://localhost:27017'
const DB_NAME = process.env.DB_NAME ?? 'APIclase';
const USERS = 'users'
const TIENDA = 'tienda'

const client = new MongoClient(DB_URL)

const SECRET_KEY = process.env.SECRET_KEY;

if (!SECRET_KEY) {
    throw new Error('Debes definir la variable de entorno SECRET_KEY');
}

const database = client.db(DB_NAME);
const Users = database.collection(USERS);
const Tienda = database.collection(TIENDA);

app.get("/", (request, response) => {
    response.redirect("/api/users")
})

function verifyToken(request, response, next) {
    const token = request.headers.authorization?.split(" ")[1]; // formato "Bearer <token>"

    if (!token) return response.status(403).json({ message: "Token requerido" });

    try {
        request.user = jwt.verify(token, SECRET_KEY);
        next();
    } catch (err) {
        return response.status(403).json({ message: "Token inválido" });
    }
}



// GET 
app.get('/api/users/:id', async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(USERS);

    const { id } = request.params
    const results = await collection.find({ _id: new ObjectId(id) }).toArray()

    response.status(200).json(results)
})


// GET
app.get('/api/tienda',verifyToken,loginLimiter, async (request, response) => {
    const database = client.db(DB_NAME);
    const collection = database.collection(TIENDA);

    const results = await collection.find({}).toArray()

    response.status(200).json(results) 
})

// POST 
app.post('/api/tienda',verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const database = client.db(DB_NAME);
    const collection = database.collection(TIENDA);

    const { nombre, precio } = request.body
    const results = await collection.insertOne({ nombre, precio });

    return response.status(200).json(results)
})


// PUT
app.put('/api/tienda/:id',verifyToken, async (request, response) => {
    if (!request.is('json'))
        return response.json({ message: 'Debes proporcionar datos JSON' })

    const database = client.db(DB_NAME);
    const collection = database.collection(TIENDA);

    const { id } = request.params
    const { nombre, precio } = request.body
    const results = await collection.updateOne({ _id: new ObjectId(id) }, { $set: { nombre, precio } });

    response.status(200).json(results)
})

// DELETE
app.delete('/api/tienda/:id',verifyToken, async (request, response) => {
    const database =  client.db(DB_NAME);
    const collection = database.collection(TIENDA);

    const { id } = request.params
    const results = await collection.deleteOne({ _id: new ObjectId(id) })
    response.status(200).json(results)
})



app.post('/api/login', loginLimiter, async (request, response) => {
    try {
        const { nombre, password } = request.body;

        if (
            typeof nombre !== 'string' ||
            typeof password !== 'string' ||
            !nombre.trim() ||
            !password
        ) {
            return response.status(400).json({
                message: 'Debes proporcionar nombre y contraseña'
            });
        }

        const user = await Users.findOne({
            nombre: nombre.trim()
        });

        

        
        if (!user || typeof user.password !== 'string') {
            return response.status(401).json({
                message: 'Credenciales incorrectas'
               
            });
        }

        const correctPassword = await bcrypt.compare(
            password,
            user.password
            
        );


        if (!correctPassword) {
            return response.status(401).json({
                message: 'Credenciales incorrectas'
                
            });
        }

        const token = jwt.sign(
            {
                id: user._id.toString(),
                nombre: user.nombre
            },
            SECRET_KEY,
            { expiresIn: '5m' }
        );

        return response.status(200).json({ token });

    } catch (error) {
        console.error('Error en login:', error);
        return response.status(500).json({
            message: 'Error interno del servidor'
        });
    }
});




app.listen(PORT, () => console.log(`Servidor web iniciado en puerto: ${PORT}`))
