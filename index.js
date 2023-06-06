const express = require('express');
const app = express();
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const stripe = require('stripe')(process.env.PAYMENT_SECRET_KEY)
const port = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

const verifyJWT = (req, res, next) => {
    const authorization = req.headers.authorization;
    if (!authorization) {
        return res.status(401).send({ error: true, message: 'unauthorized access' });
    }
    // bearer token
    const token = authorization.split(' ')[1];

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, decoded) => {
        if (error) {
            return res.status(401).send({ error: true, message: 'unauthorized access' })
        }
        req.decoded = decoded;
        next();
    })
}


const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.zgkvxtd.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        await client.connect();

        const usersCollection = client.db("bistroBD").collection("users");
        const menuCollection = client.db("bistroBD").collection("menu");
        const reviewCollection = client.db("bistroBD").collection("reviews");
        const cartCollection = client.db("bistroBD").collection("carts");
        const paymentCollection = client.db("bistroBD").collection("payments");

        // JWT Token API
        app.post('/jwt', (req, res) => {
            const user = req.body;
            const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' });
            res.send({ token });
        })

        // verifyAdmin Middleware with the mongodb connection
        // WARNING: use verifyJWT before using verifyAdmin
        const verifyAdmin = async (req, res, next) => {
            const email = req.decoded.email;
            const query = { email: email };
            const user = await usersCollection.findOne(query);

            if (user?.role !== 'admin') {
                return res.status(403).send({ error: true, message: 'forbidden access' });
            }
            next();
        }


        /**
         * 0. Do not Show secure links to those who should not see the links
         * 1. use jwt token: verifyJWT
         * 2. use verifyAdmin middleware
         * 
         */
        // users related API
        app.get('/users', verifyJWT, verifyAdmin, async (req, res) => {
            const result = await usersCollection.find().toArray();
            res.send(result);
        })

        app.post('/users', async (req, res) => {
            const user = req.body;
            const query = { email: user.email };
            const existingUser = await usersCollection.findOne(query);
            if (existingUser) {
                return res.send({ message: 'user already exists' })
            }
            const result = await usersCollection.insertOne(user);
            res.send(result);
        });

        // User Admin check with token verification
        // security layerL verifyJWT
        // email same check
        // check admin
        app.get('/users/admin/:email', verifyJWT, async (req, res) => {
            const email = req.params.email;

            if (req.decoded.email !== email) {
                res.send({ admin: false })
            }

            const query = { email: email };
            const user = await usersCollection.findOne(query);
            const result = { admin: user?.role === 'admin' }
            res.send(result);
        })

        app.patch('/users/admin/:id', async (req, res) => {
            const id = req.params.id;
            const filter = { _id: new ObjectId(id) };
            const updateDoc = {
                $set: {
                    role: 'admin'
                },
            };
            const result = await usersCollection.updateOne(filter, updateDoc);
            res.send(result);
        });

        // menu related API
        app.get('/menu', async (req, res) => {
            const result = await menuCollection.find().toArray();
            res.send(result);
        });

        app.post('/menu', verifyJWT, verifyAdmin, async (req, res) => {
            const newItem = req.body;
            const result = await menuCollection.insertOne(newItem);
            res.send(result);
        });

        app.delete('/menu/:id', verifyJWT, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await menuCollection.deleteOne(query);
            res.send(result);
        })

        // review related API
        app.get('/reviews', async (req, res) => {
            const result = await reviewCollection.find().toArray();
            res.send(result);
        });

        // cart collection APIs
        app.get('/carts', verifyJWT, async (req, res) => {
            const email = req.query.email;
            if (!email) {
                res.send([]);
            }

            const decodedEmail = req.decoded.email;
            if (email !== decodedEmail) {
                return res.status(403).send({ error: true, message: 'forbidden access' })
            }

            const query = { email: email };
            const result = await cartCollection.find(query).toArray();
            res.send(result);
        });

        app.post('/carts', async (req, res) => {
            const item = req.body;
            const result = await cartCollection.insertOne(item);
            res.send(result);
        });

        app.delete('/carts/:id', async (req, res) => {
            const id = req.params.id;
            const query = { _id: new ObjectId(id) };
            const result = await cartCollection.deleteOne(query);
            res.send(result);
        });

        // create Payment intent
        app.post('/create-payment-intent', verifyJWT, async (req, res) => {
            const { price } = req.body;
            const amount = parseInt(price * 100);
            const paymentIntent = await stripe.paymentIntents.create({
                amount: amount,
                currency: 'myr',
                payment_method_types: ['card']
            });
            res.send({
                clientSecret: paymentIntent.client_secret
            })
        });


        // Payment related API
        app.post('/payments', verifyJWT, async (req, res) => {
            const payment = req.body;

            payment.menuItems = payment.menuItems.map(item => new ObjectId(item))
            payment.cartItems = payment.cartItems.map(item => new ObjectId(item))

            const insertResult = await paymentCollection.insertOne(payment);

            const query = { _id: { $in: payment.cartItems.map(id => new ObjectId(id)) } }
            const deleteResult = await cartCollection.deleteMany(query);


            res.send({ insertResult, deleteResult });
        });

        // Admin Statistics API
        app.get('/admin-stats', verifyJWT, verifyAdmin, async (req, res) => {
            const users = await usersCollection.estimatedDocumentCount();
            const products = await menuCollection.estimatedDocumentCount();
            const orders = await paymentCollection.estimatedDocumentCount();

            // Best way to sum of the price field is to use group and sum operator
            // await paymentCollection.aggregate([
            //     {
            //         $group: {
            //             _id: null,
            //             total: { $sum: '$price' }
            //         }
            //     }
            // ]).toArray();

            const payments = await paymentCollection.find().toArray();
            const revenue = payments.reduce((sum, payment) => sum + payment.price, 0);

            res.send({
                users,
                products,
                orders,
                revenue
            })
        });

        /**
         * -----------------------------------------
         * BANGLA SYSTEM : ( second best option)
         * -----------------------------------------
         * 1. Load all payment
         * 2. for each payment get the menuitems array
         * 3. for each items in the menuitems array get the menuItem from the menuCollection
         * 4. put them in am array: allOrderedItems
         * 5. separate all order items by category
         * 6. now get the quantity by using length
         * 7. for each category use reduce to get the total amount spend on this category. 
         * 
         */
        app.get('/order-stats', verifyJWT, verifyAdmin, async (req, res) => {
            const pipeline = [
                {
                    $lookup: {
                        from: 'menu',
                        localField: 'menuItems',
                        foreignField: '_id',
                        as: 'menuItemsData'
                    }
                },
                {
                    $unwind: '$menuItemsData'
                },
                {
                    $group: {
                        _id: '$menuItemsData.category',
                        count: { $sum: 1 },
                        totalPrice: { $sum: '$menuItemsData.price' }
                    }
                },
                {
                    $project:{
                        category: '$_id',
                        count: 1,
                        total: { $round: ['$totalPrice', 2]},
                        _id: 0
                    }
                }
            ];

            const result = await paymentCollection.aggregate(pipeline).toArray();
            res.send(result);
        });




        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);



app.get('/', (req, res) => {
    res.send('Bistro Boss is Running..')
})

app.listen(port, () => {
    console.log(`Bistro Boss is Running on port ${port}`);
})