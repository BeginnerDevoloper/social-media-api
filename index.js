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
const multer=require('multer')
const winston = require('winston');
const {Storage}= require("google-cloud/storage")
const upload= multer({dest:'/uploads'})
//const cron= require('node-cron');
//const MongoClient = require('mongodb')
const { combine, timestamp, label, printf } = winston.format;
const { randomBytes } = require('crypto');
app.use ( cors ( 
    {
        origin : '*' ,
        optionsSuccessStatus : 200
    }
) ) ;

require('dotenv').config();
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, 
});
app.use(limiter)
app.use ( express . json ( ) ) ;
app.use ( cookieParser ( ) ) ;
function checkApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'] || req.query.apiKey;
    if (!apiKey) {
      return res.status(401).json({error: 'API key is missing'});
    }
   
    if (apiKey !== 'validApiKey') {
      return res.status(401).json({error: 'Invalid API key'});
    }
    next();
  }



const myFormat = printf(({ level, message, label, timestamp }) => {
  return `${timestamp} [${label}] ${level}: ${message}`;
});


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

  
  app.get('/protected', checkApiKey, (req, res) => {
    res.json({message: 'API key validated'});
  });
  
const  privateKey = fs . readFileSync ( './private.pem' ,  'utf-8' ) ;
const  publicKey = fs . readFileSync ( './public.pem' ,  'utf-8' ) ;
const storage= new Storage({
    keyFilename:process.env[name],
    projectId:process.env[id]
})
app.get ( '/' ,  ( req ,  res )  =>  {
    res . send ( 'Hello World!' ) ;
    }
) ;

const  userSchema = new  mongoose . Schema ( {
    id: Number,
    profile_picture_id:Number,
    profile_picture_url:String,
    username : String ,
    password : String ,
    email : String ,
    gender: String,
    bio: String,
    dob: DateTimeFormat,
    salt: String,
    createdAt: Date
}) ;

const  User =  mongoose . model ( 'User' ,  userSchema ) ;



                                                                                                     

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
      
       try {

            mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
            const user=await mongoose.model('User').findOne({username: sanitizedUsername});
            if(!user){
                res.status(500).send('User not found');
                logger.error('User not found', Datetime.now());
            }else{
                const salt=user.salt;
                const hashedPassword=await bcrypt.hash(sanitizedPassword, salt);

  mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
  const user=await mongoose.model('User').findOne({username: sanitizedUsername, password: hashedPassword});
    if(!user){
        res.status(401).send('Username or password is incorrect');
        logger.error('Username or password is incorrect', Datetime.now());
    }else{
        
      
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

app.delete('/delete',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const username = req.body.username;
    const password = req.body.password;
    const sanitizedPassword = sanitize(password);
    const sanitizedUsername = sanitize(username);
    if(token){
    
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

app.put('/user',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const username = req.body.username;
    const password = req.body.password;
    const bio= req.body.bio;
    
 
    const sanitizedPassword = sanitize(password);
    const sanitizedUsername = sanitize(username);
    const sanitizedbio = sanitize(bio);
    if(token){

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
app.get('/user',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const username = req.body.username;
    const sanitizedUsername = sanitize(username);
    if(token){
    
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const result=await mongoose.model('User').findOne({username: sanitizedUsername},{username:1,email:1,profile_picture_url:1,dob:1,gender:1});
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
app.post('/register', upload.single('image'), checkApiKey, [
    check('username', 'Username is too short').isLength({ min: 4 }),
    check('password', 'Password is too short').isLength({ min: 4 }),
    check('email', 'Email is not valid').isEmail(),
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ errors: errors.array() });
    }
  
    const { username, password, email, gender, bio, dob } = req.body;
    const label = ['Male', 'Female', null];
  
    if (label.includes(gender)) {
      res.send('Invalid gender');
      logger.error('Invalid gender was given', Datetime.now());
    } else {
      const sanitizedUsername = sanitize(username);
      const sanitizedPassword = sanitize(password);
      const sanitizedEmail = sanitize(email);
      const sanitizedBio = sanitize(bio);
  
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(sanitizedPassword, salt);
  
      const id = randomBytes(16).toString('hex');
      const profile_picture_id = randomBytes(16).toString('hex');
      const bucket = storage.bucket(process.env[bucket]);
      const file = bucket.file(profile_picture_id);
      const imageFile = req.file;
  
      try {
        const options = {
          resumable: false,
          metadata: {
            contentType: imageFile.mimetype,
          },
        };
  
        await file.save(imageFile.buffer, options);
        const publicUrl = `https://storage.googleapis.com/${bucket.name}/${file.name}`;
  
        const user = new User({
          id: id,
          profile_picture_id: profile_picture_id,
          profile_picture_url: publicUrl,
          username: sanitizedUsername,
          password: hashedPassword,
          email: sanitizedEmail,
          gender: gender,
          bio: sanitizedBio,
          dob: dob,
          salt: salt,
          createdAt: Date.now(),
        });
  
        mongoose.connect(process.env[url], { useNewUrlParser: true, useUnifiedTopology: true });
        await user.save();
  
        const token = jwt.sign({ userId: id }, privateKey, { algorithm: "RS256" }, function (err, token) {
          if (err) {
            res.status(500).send("Internal server error");
            logger.error(err, Date.now());
          } else {
            res.cookie("jwt", token, { httpOnly: true });
            res.send("Cookie set successfully");
            logger.info('User registered successfully');
          }
        });
  
      } catch (error) {
        res.status(500).send("Internal Server Error");
        logger.error(error, Datetime.now());
      } finally {
        if (req.file && req.file.path) {
          fs.unlink(req.file.path, (err) => {
            if (err) {
              logger.error(error, Datetime.now());
            }
          });
        }
        mongoose.connection.close();
      }
    }
  });
  
app.post('/friendreq',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const friend = req.body.friend;
    const sanitizedFriend = sanitize(friend);
    if(token){
    
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

app.delete('/friend',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const friend = req.body.friend;
    const sanitizedFriend = sanitize(friend);
    if(token){
  
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
app.get('/friends',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    if(token){

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

app.post('/friend',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const friend = req.body.friend;
    const sanitizedFriend = sanitize(friend);
    if(token){
 
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

const post=mongoose.model('Post', post);

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

    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const user=await mongoose.model('User').find({id: id});
            if(!user){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());
            }else{
           
              
  
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

app.delete('/post',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post_id = req.body.post_id;
    if(token){

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

app.get('/post',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post_id = req.body.post_id;
    if(token){
  
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

app.put('/like',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post_id = req.body.post_id;
    if(token){

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

app.put('/unlike',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post_id = req.body.post_id;
    if(token){

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

app.post('/comment',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const username=req.body.username;
    const profile_picture_url=req.body.profile_picture_url;
    const post_id = req.body.post_id;
    const comment = req.body.comment;
    const sanitizedComment = sanitize(comment);
    if(token){
  
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const post=await mongoose.model('Post').find({post_id: post_id}, {commentCount: 1});
        if(!post){
            res.status(404).send('Post not found');
            logger.error('Post not found',Datetime.now())
        }else{
            const result=await mongoose.model('Post').updateOne({post_id: post_id}, {$addToSet: {comments: {comment: sanitizedComment, created_by: username,profile_picture_url:profile_picture_url}}});
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
async function deleteFileFromBucketById(fileId) {
    const bucket = storage.bucket(process.env[bucket]);
    const file = bucket.file(fileId);
    await file.delete();
    console.log(`File with ID ${fileId} deleted successfully.`);
  }
  
app.delete('/comment',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post_id = req.body.post_id;
    const comment_id = req.body.comment_id;
    const username=req.body.username;
    const profile_picture_url=profile_picture_url;
    if(token){

    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const post=await mongoose.model('Post').find({post_id: post_id}, {comments: 1,created_by:1});
        if(!post){
            res.status(404).send('Post not found');
            logger.error('Post not found',Datetime.now())
        }else{
            if (created_by!==username){
                res.status(401).send("YOu are not authorised to do this action ")
                logger.error("User not authorised to do action",DateTime.now())
            }
            else{
            const result=await mongoose.model('Post').updateOne({post_id: post_id}, {$pull: {comments: {comment_id: comment_id, created_by: username,profile_picture_url}}});
            res.status(200).send('Comment deleted successfully')
            logger.info('Comment deleted successfully',Datetime.now())
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
        logger.error('You are not logged in',Datetime.now())
    }
});

app.get('/comment',checkApiKey, async (req, res) => {
    const post_id = req.body.post_id;
    const start = req.body.start;
    const end = req.body.end;
    if(token){

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

app.get('/user',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const username = req.body.username;
    if(token){
         
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const user=await mongoose.model('User').find({username:username}, {username: 1, bio: 1, profile_picture_id: 1});
        if(!user){
            res.status(404).send('User not found');
            logger.error('User not found',Datetime.now())
        }else{
            res.status(200).send(user);
            logger.info('User found successfully',Datetime.now())
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