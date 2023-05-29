const  express = require ( 'express' ) ;
const  app =  express ( ) ;
const  port =  3000 ;
const  cors = require ( 'cors' ) ;
const https=require('https')
const  bcrypt = require ( 'bcrypt' ) ;
const  cookieParser = require ( 'cookie-parser' ) ;
const  jwt = require ( 'jsonwebtoken' ) ;
const mongoose = require('mongoose');
const ca = [fs.readFileSync(__dirname + "/ssl/ca.pem")];
const rateLimit=require('express-rate-limiter')
const fs = require('fs');
const multer=require('multer')
const winston = require('winston');
const {Storage}= require("google-cloud/storage")
const upload= multer({dest:'/uploads'})
const ffmpeg= require('ffmpeg')
//const cron= require('node-cron');
//const MongoClient = require('mongodb')
const { combine, timestamp, label, printf } = winston.format;
const { Client } = require('@elastic/elasticsearch');
const http= require('http').createServer(app)
const io=require('socket.io')(http)
const AWS =require('aws-sdk')
const elasticClient = new Client({
  node:process.env['node']
});

const { check, validationResult } = require('express-validator');
const {v4: uuidv4}=require('uuid')
const nodemailer=require('nodemailer');
const redis = require('ioredis');
const { promisify } = require('util');
const {spawn}=require('spawn')
const redisClient = redis.createClient({
    host: process.env['host'],
    port: process.env['port'],
    password: process.env['password'],
  tls: {
    key: fs.readFileSync(__dirname + '/ssl/client.pem'),
    cert: fs.readFileSync(__dirname + '/ssl/client.pem'),
    ca: fs.readFileSync(__dirname + '/ssl/ca.pem'),
    rejectUnauthorized: false,
    // Enable other SSL options if needed
  },
});

const  transporter= nodemailer.createTransport({
   service:'Gmail',
   auth:{
    user:process.env['user'],
    pass:process.env['pass']
   }
})
app.use ( cors ( 
    {
        origin : '*' ,
        optionsSuccessStatus : 200
    }
) ) ;
const s3= new AWS.S3({
 accessKeyId:process.env['acessKeyId'],
 secretAccessKey:process.env['secretAccessKey'],
})
require('dotenv').config();
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, 
});
app.use(limiter)
app.use ( express . json ( ) ) ;
app.use ( cookieParser ( ) ) ;
app.use ( express . urlencoded ( { extended :  true  } ) ) ;

const apiKeySchema = new mongoose.Schema({
    key: String,
    createdAt: Date
})
const apiKeyModel = mongoose.model('ApiKey', apiKeySchema);
async function checkApiKey(req, res, next) {
    const apiKey = req.headers['x-api-key'] || req.query.apiKey;
    if (!apiKey) {
      return res.status(401).json({error: 'API key is missing'});
    }
   try{
    mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true})
    const result=await apiKeyModel.findOne({key: apiKey});
    if (!result) {
      return res.status(401).json({error: 'Invalid API key'});
    }
}catch(error){
    

    res.status(500).send("Internal Server Error");
    logger.error(error,Datetime.now());
}finally{
    mongoose.connection.close();
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
async function compress() {
    try {
        const process = new ffmpeg('./uploads/video.mp4');
        process.then(function (video) {
            video
                .setVideoSize('640x480', true, true, '#fff')
                .save('./uploads/video_compressed.mp4', function (error, file) {
                    if (!error)
                        console.log('Video file: ' + file);
                });
        }, function (err) {
            console.log('Error: ' + err);
        });
    } catch (e) {
        console.log(e.code);
        console.log(e.msg);
    }
}
  
 
  
const  privateKey = fs . readFileSync ( './private.pem' ,  'utf-8' ) ;
const  publicKey = fs . readFileSync ( './public.pem' ,  'utf-8' ) ;
const storage= new Storage({
    keyFilename:process.env[name],
    projectId:process.env[id]
})
const privateKey = fs.readFileSync('path/to/your/private-key.pem');
const certificate = fs.readFileSync('path/to/your/certificate.pem');
const ca = fs.readFileSync('path/to/your/ca.pem');

app ( '/' ,  ( req ,  res )  =>  {
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
    const profile_picture_id=req.body.profile_picture_id;
    if(token){
    
    try {
        await deleteFileFromBucketById(profile_picture_id)
 

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

app.put('/user',checkApiKey,upload.single('image'), async (req, res) => {
    const token = req.cookies.jwt;
    const username = req.body.username;
    const password = req.body.password;
    const bio= req.body.bio;
    const profile_picture_idd=req.body.profile_picture_id;
 
    const sanitizedPassword = sanitize(password);
    const sanitizedUsername = sanitize(username);
    const sanitizedbio = sanitize(bio);
    if(token){

    try { 
       await  deleteFileFromBucketById(profile_picture_idd)
       const profile_picture_id = uuidv4();
       const bucket = storage.bucket(process.env[bucket]);
       const file = bucket.file(profile_picture_id);
       const imageFile = req.file;
   
      
         const options = {
           resumable: false,
           metadata: {
             contentType: imageFile.mimetype,
           },
        }
       
   
         await file.save(imageFile.buffer, options);
         const publicUrl = `https://storage.googleapis.com/${bucket.name}/${file.name}`;
       
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const user=await mongoose.model('User').update({username: sanitizedUsername}, {bio: sanitizedbio},{
            profile_picture_id:profile
        },{profile_picture_url:profile_picture_url});
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
  
   redisClient(username, async (err, result) => {
        if (result) {
            res.status(200).send(result);
            logger.info('User found in cache', Datetime.now());
        } else {
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const result=await mongoose.model('User').findOne({username: sanitizedUsername},{username:1,email:1,profile_picture_url:1,dob:1,gender:1,fastatus:1});


            if(!result){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());
            }else{
               
                redisClient.setex(username, 3600, JSON.stringify(result));  
                res.status(200).send(result)
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
            redisClient.quit();
        }
    }
})
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
  
      const id = uuidv4();
      const profile_picture_id = uuidv4();
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

  // Index a user
  elasticClient.index({
    index: 'users',
    body: {
      username: sanitizedUsername
    }
  }, (err, resp) => { 
if(err){
    logger.error(err, Date.now());
}else{
    res.status(200).send('User registered successfully');
    logger.info('Index created succesfully', Date.now());
}
   });
  
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
    const username=req.body.username;
    const profile_picture_url=req.body.profile_picture_url;
    if(token){
    
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const user=await mongoose.model('User').update({id: id}, {$push: {friends_requests: sanitizedFriend,username:1,profile_picture_url:1}});

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
    const username=req.body.username;
    const profile_picture_url=req.body.profile_picture_url;
    if(token){
  
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const user=await mongoose.model('User').find({id: id});
            if(!user){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());

            }else{
                const user=await mongoose.model('User').update({id: id}, {$pull: {friends: sanitizedFriend,profile_picture_url:profile_picture_url,username:username}});
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
redisClient(id, async (err, result) => {
   

    if (result) {
        res.status(200).send(JSON.parse(result));
        logger.info('Friends fetched successfully', Datetime.now());    
    } else {

    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const result=await mongoose.model('User').find({id: id}, {friends: 1, friends_requests: 1,username:1,profile_picture_url:1});

            if(!result){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now()); 
            }else{
               redisClient.setex(id, 3600, JSON.stringify(result));
                res.status(200).send(result)
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
            redisClient.quit();
        }
    }
    })
}else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }
})


app.post('/friend',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;rr
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

app.post('/post',checkApiKey,upload.single('file'),async(req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const post = req.body.post;
    const sanitizedPost = sanitize(post);
    const visibility = req.body.visibility;
    const sanitizedVisibility = sanitize(visibility);
    const title = req.body.title;
    const sanitizedTitle = sanitize(title);
    let image=req.file;   
    if(token){

    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const user=await mongoose.model('User').find({id: id});
            if(!user){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());
            }else{
           
              if (file){
            //compress the video
            image= await compress();
            const fileId=uuidv4();      
                

                const bucket = storage.bucket(process.env[post_bucket]);
                const file = bucket.file(fileId);
                const blobStream = file.createWriteStream({
                    metadata: {
                        contentType: file.mimetype
                    }
                });
                blobStream.on('error', (error) => {
                    res.status(500).send("Internal Server Error");
                    logger.error(error,Datetime.now());
                });
                blobStream.on('finish', async () => {
                    const image_url = `https://storage.googleapis.com/${bucket.name}/${file.name}`;
                    const post=new Post({title:sanitizedTitle,created_by: id,content:sanitizedPost, visibility: sanitizedVisibility,post_id:post_id, createdAt: Date.now(),image_id:fileId,image_url:image_url});
                    const result=await post.save();
                    res.status(200).send('Post added successfully')
                    logger.info('Post added successfully', Datetime.now());
                });
                blobStream.end(req.file.buffer);
            }else{
            
                  
                     const post=new Post({title:sanitizedTitle,created_by: id,content:sanitizedPost, visibility: sanitizedVisibility,post_id:post_id, createdAt: Date.now()});
                const result=await post.save();
                res.status(200).send('Post added successfully')
                logger.info('Post added successfully', Datetime.now());
            }
            elasticClient.index({
                index: 'posts',
                body: {
                  title: sanitizedTitle,
                content: sanitizedPost,
                }
              }, (err, resp) => { 
            if(err){
                logger.error(err, Date.now());
            }else{
                res.status(200).send('Post added successfully');
                logger.info('Index created succesfully', Date.now());
            }
              });
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now()); 
        }finally{
          
            if (req.file && req.file.path) {
      
            fs.unlink(req.file.path, (err) => {
                if (err) {                                                                                              
                    logger.error(error, Datetime.now());
                }
            });
            
             
            mongoose.connection.close();
            }else{
                mongoose.connection.close();
            }
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
    const image_id=req.body.image_id;
    if(token){

    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const post=await mongoose.model('Post').find({post_id: post_id}, {created_by: 1,image_id:1});

            if(!post){
                res.status(404).send('User not found');
                logger.error('User not found', Datetime.now());
            }else{
                if(post.created_by!=id){
                    res.status(401).send('You are not authorized to delete this post');
                    logger.error('User not authorized to delete this post', Datetime.now());
                }else{
                    if(post.image_id){
                       
                        const bucket = storage.bucket(process.env[post_bucket]);
                        const file = bucket.file(fileId);
                        await file.delete();
                        const result=await mongoose.model('Post').deleteOne({post_id: sanitizedPost_id});
                 
                    }else{
                const result=await mongoose.model('Post').deleteOne({post_id: sanitizedPost_id});
                res.status(200).send('Post deleted successfully')
                logger.info('Post deleted successfully', Datetime.now());
                    }
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
  redisClient(id, async (err, result) => {
    if (result) {
        res.status(200).send(JSON.parse(result));
    } else {

    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const result=await mongoose.model('Post').find({created_by: id}, {title: 1, content: 1,likes: 1, commentCount: 1,visibility:1,image_id:1,image_url:1});
            if(!result){
                res.status(404).send('Post not found');
                logger.error('Post not found', Datetime.now());

            }else{      
              redisClient.setex(id, 3600, JSON.stringify(result));
                res.status(200).send(result)
            }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
            redisClient.quit();
        }
    }
})
}else{
        res.status(401).send('You are not logged in');
        logger.error('User not logged in', Datetime.now());
    }
    })


app.get('/feed',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    if(token){
  
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const result=await mongoose.model('Post').find({$or: [{visibility: 'public'}, {visibility: 'friend', created_by: {$in: mongoose.model('User').find({id: id}, {friends: 1})}}]}, {title: 1, content: 1,likes: 1, commentCount: 1,visibility:1,image_url:1,image_id:1}).limit(25);
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

app.put('/post',checkApiKey,upload.single('file'), async (req, res) => {
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
    const image_id=req.body.image_id;
    const file=req.file;
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
             if(file){  
                const bucket = storage.bucket(process.env[post_bucket]);
                const file = bucket.file(fileId);
                await file.delete();
                const newFileId=uuidv4();
                const newFile = bucket.file(newFileId);
                const blobStream = newFile.createWriteStream({
                    metadata: {
                        contentType: file.mimetype
                    }
                });
                blobStream.on('error', (error) => {
                    res.status(500).send("Internal Server Error");
                    logger.error(error,Datetime.now());
                });
                blobStream.on('finish', async () => {
                    const url = `https://storage.googleapis.com/${bucket.name}/${newFile.name}`;
                    const result=await mongoose.model('Post').updateOne({post_id: post_id}, {title: sanitizedTitle, content: sanitizedPost, visibility: sanitizedVisibility,image_id:newFileId,image_url:url});
                    res.status(200).send('Post updated successfully')
                    logger.info('Post updated successfully', Datetime.now());


                });
             }else{
                const result=await mongoose.model('Post').updateOne({post_id: post_id}, {title: sanitizedTitle, content: sanitizedPost, visibility: sanitizedVisibility});
                res.status(200).send('Post updated successfully')
                }
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
        redisClient(post_id, async (err, result) => {
            if (result) {
                res.status(200).send(JSON.parse(result));   
            } else {
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const post=await mongoose.model('Post').find({post_id: post_id}, {comments: 1});
        if(!post){
            res.status(404).send('Post not found');
            logger.error('Post not found',Datetime.now())
        }else{
            const result=await mongoose.model('Post').find({post_id: post_id}, {comments: {$slice: [start, end]}});
            redisClient.setex(post_id, 3600, JSON.stringify(result));
            res.status(200).send(result)
            logger.info('Comment deleted successfully',Datetime.now())
        }
        }catch(error){
                const jwt=req.cookies.jwt;
                const decoded=jwt.decode(jwt)
                const userId=decoded.id
                const file=req.file;
                const id=uuidv4();
                           const bucket=storage.bucket(process.env[bucket]);
                const blob=bucket.file(id);
                const blobStream=blob.createWriteStream();
                blobStream.on('finish',()=>{
                    res.status(200).send("Ok");
                    logger.info('Image post created successfully',Datetime.now())
                })
                blobStream.on('error',(err)=>{
                    res.status(500).send("Internal Server Error")
                    logger.error(err,Datetime.now());
                })
                const url=`https://storage.googleapis.com/${process.env[bucket]}/${id}`
                try{
                    const result=await mongoose.model('User').updateOne({id:userId},{$push:{posts:{id:id,url:url}}});
                    res.status(200).send("Ok");
                    logger.info('Image post created successfully',Datetime.now())
                }catch(error){
                    res.status(500).send("Internal Server Error")
                    logger.error(error,Datetime.now());
                }finally{
                    mongoose.connection.close();
                    redisClient.quit();
                }
            }
        }
        
    })
           
           
            
        } else{
        res.status(401).send('You are not logged in');
        logger.error('User is not logged in',Datetime.now())
        }
    })

app('/user',checkApiKey, async (req, res) => {
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

app('/friend',checkApiKey, async (req, res) => {    
    const token = req.cookies.jwt;
    const decoded=jwt.decode(token);
    const id=decoded.id;
    const username = req.body.username;

   const user= client(username,async(err,user)=>{
        if(err) throw err;
    })
        if(user){
            res.status(200).send(user);
        }else{

    

   
  
    if(token){
         mongoose.connnect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
    try {
        const user=await mongoose.model('User').find({username:username}, {username: 1, bio: 1, profile_picture_id: 1});
        if(!user){
            res.status(404).send('User not found');

        }else{
            
            client.setex(username,3600,JSON.stringify(user));
            res.status(200).send(user);
        }
        }catch(error){
            res.status(500).send("Internal Server Error");
        }finally{
            mongoose.connection.close();
            redisClient.quit()
        }
    }
    }
})

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
app.get('/user/posts',checkApiKey, async (req, res) => {
    const token = req.cookies.jwt;  
    const decoded=jwt.decode(token);
    const id = decoded.id;

});

app.post('/reset-password',validateApiKey,async(req,res)=>{
    const email=req.body.email;
    const jwt=req.cookies.jwt;
    const decoded=jwt.decode(jwt)
    const userId=decoded.id
    const emails=process.env[user]
    try {
        mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
        const user=await mongoose.model('User').find({email:email});
        const code=uuidv4();
        const subjectt='Email Verification Code'
        const textt=`Your code is ${code}`
        if(!user){
            res.status(404).send('User not found');
            logger.error(' User  was not found',Datetime.now())
        }else{
        
            const mailOptions={
                from:emails,
                to:email,
                subject:subjectt,
                text:textt
              }
                transporter.sendMail(mailOptions,async (err,data)=>{
                    if(err){
                        res.status(500).send("Internal Server Error");
                        logger.error(err,Datetime.now());
                    }else{
                        
                        await redisClient.set(userId,code,(err,reply)=>{
                            if(err){
                                res.status(500).send("Internal Server Error");
                            }
                            else{
                               res.status(200).send("Ok");
                            }
                        })
                    }
                    })
     
            logger.info('Code sent successfully',Datetime.now())
        }
        }catch(error){
            res.status(500).send("Internal Server Error");
            logger.error(error,Datetime.now());
            logger.error(error,Datetime.now());
        }finally{
            mongoose.connection.close();
            redisClient.quit();
        }
 
  });
app.post('/verify-password:/id',validateApiKey,async(req,res)=>{
 const{id}=req.params;
 const jwt=req.cookies.jwt;
 const decoded=jwt.decode(jwt)
 const userId=decoded.id

 try{
 const retriveOTP= await redisClient.get(userId);
    if(retriveOTP===id){
     
        const code=uuidv4();
    
        await  redisClient.setex(userId,3600,code);
        res.status(200).send(code);
        logger.info('Code verified successfully',Datetime.now())
    }else{
        res.status(401).send("Unauthorized");
        logger.error('Code verification failed',Datetime.now())
    }

}catch(error){
    res.status(500).send("Internal Server Error")
    logger.error(error,Datetime.now());
}finally{
  redisClient.quit();
}
})



app.put('/reset-password-update',validateApiKey,async(req,res)=>{
const jwt=req.cookies.jwt;
const decoded=jwt.decode(jwt)
const userId=decoded.id
const code=req.body.code;
const password=req.body.password;
try{
    redisClient(userId,async (err,reply)=>{
        if(err){
            console.log(err)
        } else{
             
        if(reply===code){
            const salt=await bcrypt.genSalt();
            const hashedPassword=await bcrypt.hash(password,salt);
            mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
            const result=await mongoose.model('User').updateOne({id:userId},{$set:{password:hashedPassword}});
            res.status(200).send("Ok");
            logger.info('Password updated successfully',Datetime.now())
        }else{
            res.status(401).send("Unauthorized");
            logger.error('Password update failed',Datetime.now())
        }
    }
    
    })
}catch(error){
    res.status(500).send("Internal Server Error")
    logger.error(error,Datetime.now());
}finally{
    redisClient.quit();
    mongoose.connection.close();
}
});


app.put('/password',validateApiKey,async(req,res)=>{
   const jwt=req.cookies.jwt;
    const decoded=jwt.decode(jwt)
    const userId=decoded.id
    const username=req.body.username
    const currentpassword=req.body.password;
    const newpassword=req.body.password;

 try{
    mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
    const salt= await mongoose.model('User').find({username:username},{salt:1});
      const hashedPassword=await bcrypt.hash(currentpassword,salt);
        const result=await mongoose.model('User').find({id:userId,password:hashedPassword});
        if(!result){
            res.status(401).send("Unauthorized");
            logger.error('Password update failed',Datetime.now())
        }else{
            const newsalt=await bcrypt.genSalt();
            const newhashedPassword=await bcrypt.hash(newpassword,newsalt);
            const result=await mongoose.model('User').updateOne({id:userId},{$set:{password:newhashedPassword}});
            res.status(200).send("Ok");
            logger.info('Password updated successfully',Datetime.now())
        }
 }catch(error){
     res.status(500).send("Internal Server Error")
    }finally{
        mongoose.connection.close();
    }
 

});

app.post('/2fa-enable',validateApiKey,async(req,res)=>{
    const jwt=req.cookies.jwt;
    const decoded=jwt.decode(jwt)
    const userId=decoded.id
    const code=uuidv4();
    const email=req.body.email;
    try{
       
        const subjectt='2FA Code'
        const textt=`Your code is ${code}`
        const mailOptions={
            from:process.env[email],
            to:email,
            subject:subjectt,
            text:textt
            }
            transporter.sendMail(mailOptions,(err,data)=>{
                if(err){
                    res.status(500).send("Internal Server Error");
                    logger.error(err,Datetime.now());
                }else{
                   res.status(200).send("Ok");
                     logger.info('2fa code sent',Datetime.now())
                }
            })
        redisClient.set(userId,code,'EX',300)

        res.status(200).send("Ok");
        logger.info('2fa code sent',Datetime.now())
    }catch(error){
        res.status(500).send("Internal Server Error")
        logger.error(error,Datetime.now());
    }finally{
        redisClient.quit();
        mongoose.connection.close();
    }
});

app.put('/2fa-enable-update',validateApiKey,async(req,res)=>{
    const jwt=req.cookies.jwt;
    const decoded=jwt.decode(jwt)
    const userId=decoded.id
    const code=req.body.code;
 
    try{
        redisClient(userId,async (err,reply)=>{
            if(err){
                res.status(500).send("Internal Server Error")
                logger.error(err,Datetime.now());
         
            }
            if(reply===code){
                const result=await mongoose.model('User').updateOne({id:userId},{$set:{twofactor:true}});
                res.status(200).send("Ok");
                logger.info('2fa enabled successfully',Datetime.now())
            }else{
                res.status(401).send("Unauthorized");
                logger.error('2fa enable failed',Datetime.now())
            }
        })
    }catch(error){
        res.status(500).send("Internal Server Error")
        logger.error(error,Datetime.now());
    }finally{
        redisClient.quit();
        mongoose.connection.close();
    }
}
);

app.post('/2fa-disable',validateApiKey,async(req,res)=>{
    const jwt=req.cookies.jwt;
    const decoded=jwt.decode(jwt)
    const userId=decoded.id
    const code=uuidv4();
    const email=req.body.email;
    try{
        
        const subjectt='2FA Code'
        const textt=`Your code is ${code}`
        const mailOptions={
            from:process.env[email],
            to:email,
            subject:subjectt,
            text:textt
            }
            transporter.sendMail(mailOptions,(err,data)=>{
                if(err){
                    res.status(500).send("Internal Server Error");
                    logger.error(err,Datetime.now());
                }else{
                    console.log('Email sent')
                }
            })
        redisClient.set(userId,code,'EX',300)

        res.status(200).send("Ok");
        logger.info('2fa code sent',Datetime.now())
    }catch(error){
        res.status(500).send("Internal Server Error")
        logger.error(error,Datetime.now());
    }finally{
        redisClient.quit();
        mongoose.connection.close();
    }
}
);
app.put('/2fa-disable-update',validateApiKey,async(req,res)=>{
    const jwt=req.cookies.jwt;
    const decoded=jwt.decode(jwt)
    const userId=decoded.id
    const code=req.body.code;
    try{
        redisClient(userId,async (err,reply)=>{
            if(err){
               res.status(500).send("Internal Server Error")
                logger.error(err,Datetime.now());
         
            }
            if(reply===code){
                const result=await mongoose.model('User').updateOne({id:userId},{$set:{twofactor:false}});
                res.status(200).send("Ok");
                logger.info('2fa disabled successfully',Datetime.now())
            }else{
                res.status(401).send("Unauthorized");
                logger.error('2fa disable failed',Datetime.now())
            }
        })
    }catch(error){
        res.status(500).send("Internal Server Error")
        logger.error(error,Datetime.now());
    }finally{
        redisClient.quit();
        mongoose.connection.close();
    }
}
);

app.post('/verify-email',async(req,res)=>{
    const userId=req.query.id;
    try{
        const result=await mongoose.model('User').updateOne({id:userId},{$set:{emailVerified:true}});
        res.status(200).send("Ok");
        logger.info('Email verified successfully',Datetime.now())
    }catch(error){
        res.status(500).send("Internal Server Error")
        logger.error(error,Datetime.now());
    }finally{
        mongoose.connection.close();
    }
}
);


       

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
  app.get('/search', async (req, res) => {
    const query = req.query.q;
    const type=req.body.type;

    if (!query) {
      res.status(400).send('Please provide a search query.');
      return;
    }
  if (type==='posts'){
    try {
      const postResp = await elasticClient.search({
        index: 'posts',
        body: {
          query: {
            match_phrase: {
              title: {
                query: query
              },
              content: {
                query: query
              }
            }
          }
        }
      });
      res.status(200).send({ posts: postResp.hits.hits});
    

     
    } catch (err) {
      res.status(500).send('Error searching posts and users.');
    }
  }else{
    const userResp = await elasticClient.search({
        index: 'users',
        body: {
          query: {
            match_phrase: {
              username: {
                query: query
              }
            }
          }

        }
      });
    
      res.status(200).send({users: userResp.hits.hits });
    
}
});

const liveStreamSchema=new mongoose.Schema({
    id:String,
    title:String,
    userId:String,
    createdAt:Date,
    roomId:String
});
const Livestream=mongoose.model('Livestream',liveStreamSchema);
const tempDir ='./temp';
const chatMessageSchema= new mongoose.Schema({
    room:String,
    username:String,
    message:String,
    timestamp:{type:Date,default:Date.now},
    profile_picture_url:String
})
const ChatMessage=mongoose.model('ChatMessage',chatMessageSchema);
io.on('connection', (socket) => {
logger.info('User connected',Datetime.now())
});
socket.on('startLivestream',async ()=>{
  const room=socket.id;

  socket.join(room);

    const jwt=req.cookies.jwt;
    const decoded=jwt.decode(jwt)
    const userId=decoded.id
    const title=req.body.title;
 const fileName=`${socket.id}.ts`
 const filePath=`${tempDir}/${fileName}`
 const writeStream=fs.createWriteStream(filePath);
 const liveStreamid=uuidv4();
 
    const livestream=new Livestream({
        id:liveStreamid,
        title:title,
        userId:userId,
        createdAt:Date.now(),
        roomId:room
    });
    await livestream.save();
   
    socket.on('stream',(chunk)=>{
        writeStream.write(chunk);
socket.to(room),emit('stream',chunk);
    });
});
socket.on('leaveRoom',async()=>{
    socket.leave(room);
})
socket.on('chatMessage',async (message)=>{
    const jwt=req.cookies.jwt;
    const decoded=jwt.decode(jwt)
    const userId=decoded.id
    const username=req.body.username;
    const room=req.body.room;
    const post_id=req.body.post_id;
    const chatMessage=new ChatMessage({
        room:room,
        username:username,
        message:message,
        timestamp:Date.now(),
        username:req.body.username,
        profile_picture_url:req.body.profile_picture_url
    });
    await chatMessage.save();
    socket.to(room).emit('chatMessage',message);
});
socket.on('like',async (data)=>{
 const {room}=data;
 const jwt=req.cookies.jwt;
    const decoded=jwt.decode(jwt)
    const userId=decoded.id
    const username=req.body.username;
    const profile_picture_url=req.body.profile_picture_url;
    const post_id=req.body.post_id;
    const post=await mongoose.model('Post').find({post_id: post_id}, {likes: 1});
    if(!post){
        res.status(404).send('Post not found');
        logger.error('Post not found',Datetime.now())
    }else{
        const result=await mongoose.model('Post').updateOne({post_id: post_id}, {$addToSet: {likes: id}});
        socket.to(room).emit('like',data);
        logger.info('Post liked successfully',Datetime.now())
    }
});
socket.on('joinroom',(room)=>{
    socket.join(room)
})
socket.on('endLivestream',async ()=>{
 socket.leave(room)
    const jwt=req.cookies.jwt;
    const decoded=jwt.decode(jwt)
    const userId=decoded.id
    const title=req.body.title;
    const liveStreamid=req.body.liveStreamid;
  
    const livestream=await Livestream.findOne({id:liveStreamid},{userId:1});
    if(livestream.userId!=userId){
        res.status(401).send("Unauthorized");
        logger.error('User not authorized',Datetime.now())
    }
    fs.writeStream.close();
    const compressedFileName=`${socket.id}.mp4`;
    const compressedFilePath=`${tempDir}/${compressedFileName}`;

    try{
        await promisify(spwan)('ffmpeg',[
            '-i',
            filePath,
            '-c:v',
            'libx264',
            '-preset',
            'fast',
            '-c:a',
            'aac',
            compressedFilePath
        ])
        const params={
            Bucket:process.env[bucket],
            Key:compressedFileName,
            Body:fs.createReadStream(compressedFilePath),
        }
        const uploadedVideo=await s3.upload(params).promise();
        const videoData={
        userId:socket.id,
        videoUrl:uploadedVideo.Location,
    };
    await promisify(fs.unlink)(filePath);
    await promisify(fs.unlink)(compressedFilePath);
    app.delete('/video/:id',async(req,res)=>{
        const videoId=req.params.videoId;
        const jwt=req.cookies.jwt;
         const decoded=jwt.decode(jwt)
         const userId=decoded.id
         mongoose.connect(process.env[url], {useNewUrlParser: true, useUnifiedTopology: true});
         await mongoose.findOne({id:videoId},{userId:1});
         if(livestream.userId!=userId){
             res.status(401).send("Unauthorized");
             logger.error('User not authorized',Datetime.now())
         }else{
             await mongoose.deleteOne({id:videoId});
             res.status(200).send("Ok");
             logger.info('Video deleted successfully',Datetime.now())
         }
     });
     
    }catch(err){
        logger.error(err,Datetime.now());
    }


})
socket.on('disconnect', () => {
    logger.info('User disconnected',Datetime.now())
});




const server = https.createServer(options, app);

server.listen(3000, () => {
  console.log('Server listening on port 3000 with SSL');
});
