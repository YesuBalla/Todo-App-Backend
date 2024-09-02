const express = require('express');
const app = express() ;
const cors = require('cors');

app.use(cors());
app.use(express.json());

const {open} = require('sqlite');
const sqlite3 = require('sqlite3');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const path = require('path');
const dbPath = path.join(__dirname, 'todoDatabase.db');

let db = null; 
const initializeDBAndServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });
        app.listen(8080, () => {
            console.log('Server is running on port 8080');
        });
    } catch (error) {
        console.error(`DB Error: ${error.message}`);
        process.exit(1);
    }
};

initializeDBAndServer();

//Authentication 
const authenticateToken = (request, response, next) => {
    let jwtToken;
    const authHeader = request.headers["authorization"];
    if (authHeader !== undefined) {
      jwtToken = authHeader.split(" ")[1];
    }
    if (jwtToken === undefined) {
      response.status(401);
      response.send("Invalid JWT Token");
    } else {
      jwt.verify(jwtToken, "TOP", (error, payload) => {
        if (error) {
          response.status(401);
          response.send("Invalid JWT Token");
        } else {
          request.username = payload.username;
          request.userId = payload.userId;
          next();
        }
      });
    }
  };
  

//Register API
app.post("/register/", async (request, response) => {
    try {
        const { id, username, email, password } = request.body;
        const selectUserQuery = `
          SELECT * 
          FROM users
          WHERE email = ?;
        `;
        const dbUser = await db.get(selectUserQuery, [email]);

        if (dbUser === undefined) {
            if (password.length < 3) {
                response.status(400).send("Password is too short");
            } else {
                const hashedPassword = await bcrypt.hash(password, 10);
                const createUserQuery = `
                  INSERT INTO 
                      users (id, name, email, password)
                  VALUES 
                      (?, ?, ?, ?);
                `;
                await db.run(createUserQuery, [id, username, email, hashedPassword]);
                response.send("User created successfully");
            }
        } else {
            response.status(400).send("User already exists");
        }
    } catch (error) {
        console.error(error);
        response.status(500).send("Internal server error");
    }
});


//Login API  
app.post("/login/", async (request, response) => {
    const { email, password } = request.body;
    const selectUserQuery = `
      SELECT * 
      FROM users 
      WHERE email = ?;
    `;
  
    try {
      const dbUser = await db.get(selectUserQuery, [email]);
  
      if (dbUser === undefined) {
        response.status(400).send("Invalid user");
        return;
      }
  
      const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
  
      if (isPasswordMatched) {
        const payload = { username: dbUser.name, userId: dbUser.id };
        const jwtToken = jwt.sign(payload, "TOP"); 
        response.send({ jwtToken });
      } else {
        response.status(400).send("Invalid password");
      }
    } catch (error) {
      console.error("Error during login:", error);
      response.status(500).send("Internal server error");
    }
});
  
//Get API 
app.get("/todos/", authenticateToken, async (request, response) => {
    const {userId} = request;
    const getTodosQuery = `
      SELECT *
      FROM todos
      WHERE user_id = '${userId}';
      `;
    const todos = await db.all(getTodosQuery);
    response.send(todos);
  });

  app.post("/todos/", authenticateToken, async (request, response) => {
    const { id, userId, title, priority, status, category} = request.body; 
    console.log(id, userId, title, priority, status, category)
  
    const addTodoQuery = `
      INSERT INTO
        todos (
            id, user_id, title, priority, status, category
        )
      VALUES 
        (?, ?, ?, ?, ?, ?);
    `;
    
    try {
      // Execute the query with parameters
      await db.run(addTodoQuery, [id, userId, title, priority, status, category]);
      response.status(201).send("Todo Successfully Added");
    } catch (error) {
      console.error('Error adding todo:', error);
      response.status(500).send("Error adding todo");
    }
  });
  
  