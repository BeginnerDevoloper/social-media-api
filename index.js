const  express = require ( 'express' ) ;
const  app =  express ( ) ;
const  port =  3000 ;
const  cors = require ( 'cors' ) ;
//import bycrypt ,cookie parser and jwt
const  bcrypt = require ( 'bcrypt' ) ;
const  cookieParser = require ( 'cookie-parser' ) ;
const  jwt = require ( 'jsonwebtoken' ) ;
const mongoose = require('mongoose');
const rateLimit=require('express-rate-limiter')
const fs = require('fs');
const winston = require('winston');
const cron= require('node-cron');
const MongoClient = require('mongodb')
const { combine, timestamp, label, printf } = winston.format;
const { randomBytes } = require('crypto');
app.use ( cors ( 
    {
        origin : 'http://localhost:4200' ,
        optionsSuccessStatus : 200
    }
) ) ;
//setup env
require('dotenv').config();
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});
app.use(limiter)
app.use ( express . json ( ) ) ;
app.use ( cookieParser ( ) ) ;
function checkApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'] || req.query.apiKey;
    if (!apiKey) {
      return res.status(401).json({error: 'API key is missing'});
    }
    // validate the apiKey against a list of valid keys
    if (apiKey !== 'validApiKey') {
      return res.status(401).json({error: 'Invalid API key'});
    }
    next();
  }


// define a custom log format
const myFormat = printf(({ level, message, label, timestamp }) => {
  return `${timestamp} [${label}] ${level}: ${message}`;
});

// create a logger instance that writes to a file
const logger = winston.createLogger({
  format: combine(
    label({ label: 'my-app' }),
    timestamp(),
    myFormat
  ),
  transports: [
    new winston.transports.File({ filename: 'logfile.log' })
  ]
});

  
  // use the middleware for a specific route
  app.get('/protected', checkApiKey, (req, res) => {
    res.json({message: 'API key validated'});
  });
  
//import the private and public key using fs
const  privateKey = fs . readFileSync ( './private.pem' ,  'utf-8' ) ;
const  publicKey = fs . readFileSync ( './public.pem' ,  'utf-8' ) ;

app.get ( '/' ,  ( req ,  res )  =>  {
    res . send ( 'Hello World!' ) ;
    }
) ;
//create user schema
const  userSchema = new  mongoose . Schema ( {
    id: Number,
    username : String ,
    password : String ,
    email : String ,
    gender: String,
    bio: String,
    dob: DateTimeFormat,
    salt: String,
    createdAt: Date
}) ;
//make the user schema with the username optional
const  User =  mongoose . model ( 'User' ,  userSchema ) ;

//make the register route with httponlycookie jwt rsa 256 and save the user id and hash and salt the password
app.post ( '/register' ,checkApiKey,  async  ( req ,  res )  =>  {

    const  username = req . body . username ;
    const  password = req . body . password ;
    const  email = req . body . email ;
    const gender= req.body.gender;
    const bio= req.body.bio;
    const dob= req.body.dob;
//validate and sanitize the data using express validator and sanitize
    req . check ( 'username' ,  'Username is too short' ) . isLength ( {  min :  4  } ) ;
    req . check ( 'password' ,  'Password is too short' ) . isLength ( {  min :  4  } ) ;
    req . check ( 'email' ,  'Email is not valid' ) . isEmail ( ) ;
    //validate the gender
    //f gener 
    const label=['Male','Female',null]
   if(label.includes(gender)){
     res.send('Invalid gender')
     logger.error('Invalid gender was given',Datetime.now());
    }else{
    const  errors = req . validationErrors ( ) ;
    }
    if  ( errors )  {
        res . send ( {  errors :  errors  } ) ;
    }  else  {
         
//sanitize the data using sanitize
        
 const sanitizedUsername = sanitize(username);
    const sanitizedPassword = sanitize(password);
    const sanitizedEmail = sanitize(email);
    const sanitizedbio = sanitize(bio);
    const  salt  =  await  bcrypt . genSalt ( 10 ) ;
    const  hashedPassword  =  await  bcrypt . hash ( req . body . password ,  salt ) ;
    const user= new User({
        username: sanitizedUsername,
        password: hashedPassword,
        email: sanitizedEmail,
        gender: gender,
        bio:sanitizedbio,
        dob: dob,
        salt: salt,
        createdAt: Date.now()
    });
    try{
 //connect to mongoose and save
    mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
  await user.save()
      

        const id=randomBytes(16).toString('hex'); 
        
  const token=jwt.sign({userId: id}, privateKey, {algorithm: "RS256"}, function(err, token){
if(err){
    res.status(500).send("Internal server error");

    logger.error(err,Date.now());
}else{
  
    res.cookie("jwt", token, {httpOnly: true});
    res.send("Cookie set successfully");
    logger.info('User registered successfully');
}
    });
}catch(err){
    res.status(500).send('Error registering new user please try again.')
    logger.error(err);
}finally{
    mongoose.connection.close();
}
)
}
});
                                                                                                      

app.post('/login',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const username = req.body.username;
    const password = req.body.password;
    const sanitizedPassword = sanitize(password);
    const sanitizedUsername = sanitize(username);
    if(token){
        res.send('You are already logged in');
        logger.info('User is already logged in', Date.now());   
    }else{
       //connect to mongoose and find the user
       try {

            //connect to mngodb and get the salt
            mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
            const user=await mongoose.model('User').findOne({username: sanitizedUsername});
            if(!user){
                res.status(500).send('User not found');
                logger.error('User not found', Datetime.now());
            }else{
                const salt=user.salt;
                const hashedPassword=await bcrypt.hash(sanitizedPassword, salt);
  //connect to mongoose and find the user
  mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
  const user=await mongoose.model('User').findOne({username: sanitizedUsername, password: hashedPassword});
    if(!user){
        res.status(401).send('Username or password is incorrect');
        logger.error('Username or password is incorrect', Datetime.now());
    }else{
        //generate a ra ndom id int
      
        res.cookie("jwt", token, {httpOnly: true});
    res.status(200).send('User logged in successfully')
    logger.info('User logged in successfully', Datetime.now());

   }
}
}catch (error) {
    res.status(500).send("Internal Server Error");
    logger.error(error,Datetime.now());
   }finally{
    mongoose.disconnnect();
   }  
    }


});

app.post('/logout',checkApiKey, (req, res) => {
   try{
    res.clearCookie("jwt");
    res.send("Cookie cleared");
    logger.info('User logged out successfully', Datetime.now());
   }catch(error){
    res.status(500).send("Internal Server Error");
    logger.error(error,Datetime.now());
   }
});
//create delete route and delete the user
app.delete('/delete',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const username = req.body.username;
    const password = req.body.password;
    const sanitizedPassword = sanitize(password);
    const sanitizedUsername = sanitize(username);
    if(token){
    //connect to mongodb and delete the user
    try {
     mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
     const user=await mongoose.model('User').delete({username: sanitizedUsername});
        if(!user){
            res.status(404).send('User not found');
            logger.error('User not found', Datetime.now());
        }else{
            res.status(200).send('User deleted successfully')
            logger.info('User deleted successfully', Datetime.now());
        }
    }catch(error){
    res.status(500).send("Internal Server Error");  
    }finally{
        mongoose.connection.close();    
    }
}
    else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }
});
//create update route and update the user
app.put('/update',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const username = req.body.username;
    const password = req.body.password;
    const bio= req.body.bio;

    const sanitizedPassword = sanitize(password);
    const sanitizedUsername = sanitize(username);
    const sanitizedbio = sanitize(bio);
    if(token){
    //connect to mongodb and update the user
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const user=await mongoose.model('User').update({username: sanitizedUsername}, {bio: sanitizedbio});
            if(!user){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());     
            }else{
                res.status(200).send('User updated successfully')
                logger.info('User updated successfully', Datetime.now());
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }

});
//create get route and get the user
app.get('/user',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const username = req.body.username;
    const sanitizedUsername = sanitize(username);
    if(token){
    //connect to mongodb and get the user
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const result=await mongoose.model('User').findOne({username: sanitizedUsername});
            if(!result){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());
            }else{
                res.status(200).send(result)
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now()); 
    }
});

//create friebd realtinship system
//create post route and add the friend
app.post('/friendreq',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const friend = req.body.friend;
    const sanitizedFriend = sanitize(friend);
    if(token){
    //connect to mongodb and add the friend
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const user=await mongoose.model('User').update({id: id}, {$push: {friends_requests: sanitizedFriend}});

            if(!user){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());
            }else{
                res.status(200).send('Friend added successfully')
                logger.info('Friend added successfully', Datetime.now());
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }
});
//create delete route and delete the friend
app.delete('/friend',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const friend = req.body.friend;
    const sanitizedFriend = sanitize(friend);
    if(token){
    //connect to mongodb and delete the friend
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const user=await mongoose.model('User').find({id: id});
            if(!user){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());

            }else{
                const user=await mongoose.model('User').update({id: id}, {$pull: {friends: sanitizedFriend}});
                res.status(200).send('Friend deleted successfully')
                logger.info('Friend deleted successfully', Datetime.now());
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }
});
//create get route and get the friend and friend requests
app.get('/friends',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    if(token){
    //connect to mongodb and get the friend and friend requests
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const result=await mongoose.model('User').find({id: id}, {friends: 1, friends_requests: 1});

            if(!result){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now()); 
            }else{
                res.status(200).send(result)
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }
});
//create post route and add the friend
app.post('/friend',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const friend = req.body.friend;
    const sanitizedFriend = sanitize(friend);
    if(token){
    //connect to mongodb and add the friend
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const user=await mongoose.model('User').update({id: id}, {$push: {friends: sanitizedFriend}, $pull: {friends_requests: sanitizedFriend}});
            if(!user){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());
            }else{
                res.status(200).send('Friend added successfully')
                logger.info('Friend added successfully', Datetime.now());   
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }
});

const  Post=new mongoose.Schema({
    title:String,
    created_by:String,
    content:String,
    visibility:String,
    post_id:String,
    createdAt:Date
});
//creaate post model
const post=mongoose.model('Post', post);
//create post route and add the post
app.post('/post',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post = req.body.post;
    const sanitizedPost = sanitize(post);
    const visibility = req.body.visibility;
    const sanitizedVisibility = sanitize(visibility);
    const title = req.body.title;
    const sanitizedTitle = sanitize(title);
    if(token){
    //connect to mongodb and add the post
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const user=await mongoose.model('User').find({id: id});
            if(!user){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());
            }else{
           
              
                //create post id
                const post_id = uuid.v4();

                const post=new Post({title:sanitizedTitle,created_by: id,content:sanitizedPost, visibility: sanitizedVisibility,post_id:post_id, createdAt: Date.now()});
                const result=await post.save();
                res.status(200).send('Post added successfully')
                logger.info('Post added successfully', Datetime.now());
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now()); 
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }
});
//create delete route and delete the post
app.delete('/post',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post_id = req.body.post_id;
    if(token){
    //connect to mongodb and delete the post
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const post=await mongoose.model('Post').find({post_id: post_id}, {created_by: 1});

            if(!post){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());
            }else{
                if(post.created_by!=id){
                    res.status(401).send('You are not authorized to delete this post');
                    logger.error('User not authorized to delete this post', Datetime.now());
                }else{
                const result=await mongoose.model('Post').deleteOne({post_id: sanitizedPost_id});
                res.status(200).send('Post deleted successfully')
                logger.info('Post deleted successfully', Datetime.now());
                }
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }
});
//create get route and get the post
app.get('/post',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post_id = req.body.post_id;
    if(token){
    //connect to mongodb and get the post
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const result=await mongoose.model('Post').find({created_by: id}, {title: 1, content: 1,likes: 1, commentCount: 1,visibility:1});
            if(!result){
                res.status(404).send('Post not found');
                logger.error('Post not found', Datetime.now());

            }else{      
              
                res.status(200).send(result)
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }
});
//create a route to get 25 posts where the user is a friend and the post visibility is friend or where the post visibility is public
app.get('/feed',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    if(token){
    //connect to mongodb and get the post
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const result=await mongoose.model('Post').find({$or: [{visibility: 'public'}, {visibility: 'friend', created_by: {$in: mongoose.model('User').find({id: id}, {friends: 1})}}]}, {title: 1, content: 1,likes: 1, commentCount: 1,visibility:1}).limit(25);
            if(!result){
                res.status(404).send('Post not found');
                logger.error('Post not found', Datetime.now());
            }else{
                res.status(200).send(result)
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }
});
//create a route to update the post and make sure the post belongs to the user
app.put('/post',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post_id = req.body.post_id;
    const post = req.body.post;
    const sanitizedPost = sanitize(post);
    const visibility = req.body.visibility;
    const sanitizedVisibility = sanitize(visibility);
    const title = req.body.title;
    const sanitizedTitle = sanitize(title);
    if(token){
    //connect to mongodb and update the post
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const post=await mongoose.model('Post').find({post_id: post_id}, {created_by: 1});

            if(!post){
                res.status(404).send('Post not found');
                logger.error('Post not found', Datetime.now());
            }else{
                if(post.created_by!=id){
                    res.status(401).send('You are not authorized to update this post');
                    logger.error('User not authorized to update this post', Datetime.now());
                }else{
                const result=await mongoose.model('Post').updateOne({post_id: post_id}, {title: sanitizedTitle, content: sanitizedPost, visibility: sanitizedVisibility});
                res.status(200).send('Post updated successfully')
                logger.info('Post updated successfully', Datetime.now());
                }
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();

        }
    }else{
        res.status(401).send('You are not logged in');
    }
});
//create a route to like the post
app.put('/like',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post_id = req.body.post_id;
    if(token){
    //connect to mongodb and update the post
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const post=await mongoose.model('Post').find({post_id: post_id}, {likes: 1});
        if(!post){
            res.status(404).send('Post not found');
            logger.error('Post not found', Datetime.now());
        }else{
            const result=await mongoose.model('Post').updateOne({post_id: post_id}, {$addToSet: {likes: id}});
            res.status(200).send('Post liked successfully')
            logger.info('Post liked successfully', Datetime.now());
        }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());


        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User is not logged in',Datetime.now())
    }
});
//create a route to unlike the post
app.put('/unlike',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post_id = req.body.post_id;
    if(token){
    //connect to mongodb and update the post
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const post=await mongoose.model('Post').find({post_id: post_id}, {likes: 1});
        if(!post){
            res.status(404).send('Post not found');
            logger.error('Post not found',Datetime.now())
        }else{
            const result=await mongoose.model('Post').updateOne({post_id: post_id}, {$pull: {likes: id}});
            res.status(200).send('Post unliked successfully')
     logger.info('Post unliked successfully',Datetime.now())
        }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now())
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
      logger.error('User is not logged in',Datetime.now())
    }
});
//create a route to comment on a post and create the schema too
app.post('/comment',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post_id = req.body.post_id;
    const comment = req.body.comment;
    const sanitizedComment = sanitize(comment);
    if(token){
    //connect to mongodb and update the post
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const post=await mongoose.model('Post').find({post_id: post_id}, {commentCount: 1});
        if(!post){
            res.status(404).send('Post not found');
            logger.error('Post not found',Datetime.now())
        }else{
            const result=await mongoose.model('Post').updateOne({post_id: post_id}, {$addToSet: {comments: {comment: sanitizedComment, created_by: id}}});
            res.status(200).send('Comment added successfully')
            logger.info('Comment added successfully',Datetime.now())
        }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error('Internal Server Error',Datetime.now())
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User is not logged in',Datetime.now())    
    }
});
//create a route to delete a comment on a post
app.delete('/comment',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post_id = req.body.post_id;
    const comment_id = req.body.comment_id;
    if(token){
    //connect to mongodb and update the post
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const post=await mongoose.model('Post').find({post_id: post_id}, {comments: 1});
        if(!post){
            res.status(404).send('Post not found');
            logger.error('Post not found',Datetime.now())
        }else{
            const result=await mongoose.model('Post').updateOne({post_id: post_id}, {$pull: {comments: {comment_id: comment_id, created_by: id}}});
            res.status(200).send('Comment deleted successfully')
            logger.info('Comment deleted successfully',Datetime.now())
        }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('You are not logged in',Datetime.now())
    }
});
//create a route to get the specifed ammunts of comments on a posts
app.get('/comment',checkApiKey, async (req, res) => {
    const post_id = req.body.post_id;
    const start = req.body.start;
    const end = req.body.end;
    if(token){
    //connect to mongodb and update the post
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const post=await mongoose.model('Post').find({post_id: post_id}, {comments: 1});
        if(!post){
            res.status(404).send('Post not found');
            logger.error('Post not found',Datetime.now())
        }else{
            const result=await mongoose.model('Post').find({post_id: post_id}, {comments: {$slice: [start, end]}});
            res.status(200).send(result)
            logger.info('Comment deleted successfully',Datetime.now())
        }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
        }
    }else{
        res.status(401).send('You are not logged in');
        logger.error('User is not logged in',Datetime.now())
    }
});


/*cron.schedule('0 0 * * 0', async () => {
    try {
      // connect to MongoDB
      const client = await MongoClient.connect(process.env[url], { useNewUrlParser: true, useUnifiedTopology: true });
      const db = client.db('Chat');

      // read the log files
      const errorLog = fs.readFileSync('error.log', 'utf8');
      const combinedLog = fs.readFileSync('combined.log', 'utf8');
  
      // insert the log messages into the MongoDB collection
      await db.collection('logs').insertMany([
        { type: 'error', message: errorLog },
        { type: 'info', message: combinedLog }
      ]);
  
      // close the MongoDB connection
      await client.close();
    } catch (err) {
      console.error(err);
    }
  });*/
  
  // start the cron scheduler
  //cron.start();
  


 

app.listen ( port ,  ( )  =>  {
    console . log ( `Example app listening at http://localhost:${port}` ) ;
});