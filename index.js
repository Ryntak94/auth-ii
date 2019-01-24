const express = require('express');
const helmet = require('helmet');
const knex = require('knex');
const dbConfig = require('./knexfile');
const server = express();
const db = knex(dbConfig.development);
const bcrypt = require('bcryptjs');
const session = require('express-session')
const cors = require('cors')
const jwt = require('jsonwebtoken')
server.use(express.json());
server.use(helmet());
server.use(cors());

const secret = 'secretsauce123';

function generateToken(username, department)    {

    const payload   =   {
        username,
        department
    }
    const options = {
        expiresIn: '1h',
        jwtid: '1234'
    }

    const token = jwt.sign(payload, secret, options);
    return token;
}

function protected(req, res, next)  {
    const token = req.headers.authorization;
    if(token)   {
        jwt.verify(token, secret, (err, decodedToken)   =>  {
            if(err) {
                res.status(401).json({ message: 'Invalid Token'});
            }   else {
                req.username = decodedToken.username;
                req.department = decodedToken.department;
                next();
            }
        });
    }   else {
        res.status(401).json({ message: 'no token provided' })
    }
}

const port = 3300;
server.listen(port, function() {
  console.log(`\n=== Web API Listening on http://localhost:${port} ===\n`);
});

server.post('/api/register',    (req, res)  =>  {
    const creds = req.body;
    creds.password = bcrypt.hashSync(creds.password);
    creds.username = creds.username.toUpperCase();
    creds.department = creds.department.toUpperCase();
    db('users').insert(creds)
        .then(ids   =>  {
            const token = generateToken(creds.username, creds.department)
            res.status(201).json({id: ids[0], token});
        })
        .catch(err  =>  {
            // console.log(creds)
            res.status(500).send({ err });
        })
})

server.post('/api/login',   (req, res)  =>  {
    const creds  =   req.body;
    creds.username = creds.username.toUpperCase();
    db('users').where('username', creds.username)
        .then(users =>  {
            if(users.length && bcrypt.compareSync(creds.password, users[0].password))    {
                const token = generateToken(users[0].username, users[0].department)
                res.json({ token });
            }   else {
                res.status(404).json({err: "invalid username or password"});
            }
        })
        .catch(err  =>  {
            res.status(500).json(err);
        })
})

server.get('/api/users', protected, (req, res)  =>  {
        db('users').where({department: req.department}).select("username", "department")
            .then(users =>  {
                res.json(users);
            })
})
