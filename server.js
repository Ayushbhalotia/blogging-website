import express from 'express'
import mongoose from 'mongoose'
import 'dotenv/config'
import bcrypt from "bcrypt"
import User from "./Schema/User.js"
import { nanoid } from 'nanoid'
import jwt from 'jsonwebtoken';
import cors from 'cors'
import admin from "firebase-admin";
import Blog from './Schema/Blog.js'
const { credential } = admin;
import fs from "fs";

const serviceAccountkey = JSON.parse(
  fs.readFileSync("./react-js-blog-website-bf9c9-firebase-adminsdk-ezxo0-ae42ca2537.json", "utf8")
);
import {getAuth} from "firebase-admin/auth"
import Cloudinary from "cloudinary";
const { v2: cloudinary } = Cloudinary;
// cloudinary instance has been taken 

// Use `cloudinaryV2` as your Cloudinary instance
import multer from "multer";

import Notification from "./Schema/Notification.js"
import Comment from "./Schema/Comment.js";
const storage = multer.memoryStorage(); // Store file in memory
const upload = multer({ storage }); // Use memory storage for uploaded files



const server = express();
let PORT=3000;

// written this to make an request to the server
admin.initializeApp({
credential : admin.credential.cert(serviceAccountkey)
})


let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

server.use(express.json());
// allowing to make a request from frontend running on different [ort and backend on different port ]
const cors = require("cors");

server.use(cors({
  origin: "https://ayush-blog-mern.netlify.app",  // your Netlify frontend
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true
}));


mongoose.connect(process.env.DB_LOCATION,{
    autoIndex:true
})


const cloudinaryConnect = () => {
    try{
            cloudinary.config({
                cloud_name:process.env.CLOUD_NAME,
                api_key: process.env.API_KEY,
                api_secret: process.env.API_SECRET,
            })
            // config se connect kar diye cloudinary ko and isme ye teen chiz dena hota hai yaha here 
            
    }
    catch(error) {
        console.log(error);
    }
}
// normally jo bhi waha image upload karenge uss image ko bhejenge yaha request se ab uso cloudinary me upload karenge phir image ka jo url milega usko frontend me bhejenge and phir usko frontend me show karenge 
// ab waha se post request marke yaha jo img hai frontend me usko yaha bhejenge and uskp phir cloiudionary me store karenge and uska url frontend ko bhejke show karenge 

cloudinaryConnect();

const verifyJWT = (req,res,next) =>{
// jab valid hoga access token tab ye jayega request call abck ke bpass by next function 
const authheader = req.headers['authorization'];
console.log(authheader)
const token = authheader && authheader.split(" ")[1];
// token ko bhejenge toh wo authorizatiomn me bhejenge jisko use karke usme nikal leta hai split karke as token ke sath bearer likha hoga phir token le lega and check karega null hai token yadi hai null toh token nhi diye hai ya autoristion nhi diye hai jiska matlab ki jo user kiya sko access wo logged in sign in nhi hai jisse frontend se uska nhi aaya token yaha 

if(token==null){
return res.status(401).json({error : "no access token"})
}
jwt.verify(token,process.env.SECRET_ACCESS_KEY,(err,user)=>{
    if(err){
        return res.status(403).json({error:"access token is invalid"})
    }
    // yadi token hai toh usko verify karenge jwt ka function se and usme secret key ko pass karke and yadi verify ho gya jwt kar diya ki ye secret token ke hisab se ye tken hoga toh phir err aaya toh wo hua ki token invalid and yadi user mila matlab user object mil gya and token me object me id daalte the jo ki key tha jisme user id dete the toh usko access kiye and phir next kar diye yaha 
    // req ke user me user ka id daalke next kar diye toh aage niche wala callback chalgea usme req me user myaha e user ka id mil jayega jo kiya hai iss function ko acess 
    
    req.user = user.id;
    next()
})
}

const formatdatatosend=(user)=>{
    const access_token = jwt.sign({id:user._id},process.env.SECRET_ACCESS_KEY)
// created a jjwt token and we are giving an id to this token and secret key which is a random string generate in node with crypto module with toString method and and then passe here now that jwt token is also send to the frontend as now if user wnat to login that jwt token will be checked and also that id in that jwt token not require to check whole email and password again and again andf user dont have to login again and again that jwt woill be seenand iuser can get access 

    return {
        access_token,
profile_img:user.personal_info.profile_img,
username:user.personal_info.username,
fullname : user.personal_info.fullname
    }
}


const generateusername = async(email) =>{
let username = email.split("@")[0];

let isusernamenotunique = await User.exists({"personal_info.username" : username}).then((result) => result)
isusernamenotunique ? username +=nanoid().substring(0,5): "";
return username;
// yaha se username wala thik kar diya and ab maanlo same email hua th aage niche handle kar liya hai email already exist 




}

server.post("/signup",(req,res)=>{
   let {fullname,email,password} = req.body;





   // validating the data from frontend 
   if(fullname.length<3){
    return res.status(403).json({"error" : "fullname must be atleast 3 letters long"})

   }
//    email length can be 0 then this below ode will run 

if(!email.length){
return res.status(403).json({"error":"enter email"})
}

if(!emailRegex.test(email)){
    return res.status(403).json({"error" : "email is invalid"})
}
if(!passwordRegex.test(password)){
return res.status(403).json({"error" : "password should be 6 to 20 characters long with a numeric,1 lowercase and uppercase letters"})
}

bcrypt.hash(password,10,async (err,hashed_password)=>{
    let username = await generateusername(email);
// beacause we dont want to moove further until we get username 
// actually the username which is of same username and also same gmail written email unique wil throw error at the time of saving whereas if used gmail or yahoo and sameusername then we have to save that user so to avoid ambiguity if usernsame exist then by appending some string we will save it and as now email is different with same username and different lkike yahoo then email unque will not throw error 
// as same username toh error dega isliye append 

    let user = new User({
        personal_info:{fullname,email,password:hashed_password,username}
// yaha ye fullame ek tarah se fullname : fullname hai and as sirf password likhte toh password:password likha hota jisse actual password store ho jaata jo ki nhi chahte hai isiliye alag se hashed password daale and username ko unique dena hoga as username unique ure hai and value dena hoga jabki bio and profile ka deafult hai  

    })
    user.save().then((u)=>{
        // return res.status(200).json({user:u})
        // here we are sending whole object data of user to frontend
        return res.status(200).json(formatdatatosend(u))
        // here we ARE SENDING SOME SPECIFIC DATA MENTIONED IN THE FORMATDATATOSEND 


    })
    .catch(err=>{
        if(err.code == 11000){
            return res.status(500).json("email alrady exist")
        }
        // as schema me alredy unique truehai toh same email diye signup me post request maare toh error de dega and ussi ko yaha handle kar rhe hai 

        return res.status(500).json({"error" : err.message})
        // first of all we havve used unique because of which we cant give same gmail so at first does a post request with with a gmail and then again done a post request using same gmail and then error showed of 11000 so here in this code without printing reactjs error 11000 message we have printed user exist 

    })

})

})


server.post("/signin",(req,res)=>{

    let {email,password} =req.body;
    // from sign in form here we are getting email and password 
    User.findOne({"personal_info.email":email}).then((user)=>{
        if(!user){
            return res.status(403).json({"error":"email not found"})
        }
        // yadi user hai malab findone user diya hai 
        // yadi user nhi diya iska matlab email se check kiye hai matlab email not found 

        if(!user.google_auth){
            bcrypt.compare(password,user.personal_info.password,(err,result)=>{
                // yaha callback function malab result compare ka iss function me argument se milega isko use kar sakte hai yaha issi function me bahar me iska access nhi milega 
                
                    if(err){
                        return res.status(403).json({"error":"error ocurred while login please try again"})
                    
                    }
                    if(!result){
                    return res.status(403).json({"error":"incorrect password"})
                    }
                    else{
                        return res.status(200).json(formatdatatosend(user))
                    }
                    })
                    
        }else{
            return res.status(403).json({"error" :"account was creaTED USING GOOGLE"})
        }
// yaha check kar rhe haio ki google se toh kkahi pehle se login nhi kiya 

    })
    .catch(err=>{
        console.log(err.message);
        return res.status(500).json({"error":err.message})
    })
    // here we are checking whether the email sent is actually uin the database or not if it does then block will execute if user will be fakse and themn also then bvlock will be executed and after that if block will run nd response will be email not found and also if there will be any internal error catch will handle it 
// when you have done signup then you will do signin 
// and here we are also comparing password and sending the user object data which is actually the specific data we want to send to the frontebnd with token 


})

server.post("/google-auth",async(req,res)=>{
let {access_token} =req.body;

getAuth()
.verifyIdToken(access_token)
// yaha token se user mil gya hai 
.then(async (decodeUser)=>{
let {email,name,picture } =decodeUser;
picture = picture.replace("s96-c","s384-c")

let user = await User.findOne({"personal_info.email":email}).select("personal_info.fullname personal_info.username personal_info.profile_img google_auth").then((u)=>{
    return u || null
})
.catch(err=>{
    return res.status(500).json({"error":err.message})
})
// yaha user mil gya magar uska google auth false hai matlab ye bina google ke kiya tha ab google se same gmail se kar rha hai isliyte error 

if(user){
    if(!user.google_auth){
        return res.status(403).json({"error":"this email was signed up without google. please login with password to access the account"})

    }
}
// yaha password toh hai hi nhi jo add hoga server me and phir yaha toh check bhi kar liye getauth se ki kya ye token sahi hai jo frontend se aa rha hai 

else{//signup
    let username = await generateusername(email);
    user = new User({
        personal_info : {fullname:name,email,username},
        google_auth:true
    })
    await user.save().then((u)=>{
user=u;
    })
    .catch(err=>{
        return res.status(500).json({"error":err.message})
    })
}

return res.status(200).json(formatdatatosend(user))

})
.catch(err=>{
    return res.status(500).json({"error":"failed"})
})
})





// import { Readable } from "stream"; // Use ES Module import for streams

// server.post("/get-upload", upload.single("image"), async (req, res) => {
//   try {
//     if (!req.file) {
//       return res.status(400).json({ error: "No file uploaded" });
//     }

//     // Use a Readable stream to pipe the file buffer to Cloudinary
//     const bufferStream = Readable.from(req.file.buffer);

//     cloudinary.uploader.upload_stream(
//       { folder: "codehelp" },
//       (error, result) => {
//         if (error) {
//           console.error("Cloudinary upload error:", error);
//           return res.status(500).json({ error: "Failed to upload image" });
//         }
//         res.status(200).json({ url: result.secure_url });
//       }
//     ).end(req.file.buffer); // Pass the buffer to the upload stream
//   } catch (error) {
//     console.error("Error uploading to Cloudinary:", error);
//     res.status(500).json({ error: "Failed to upload image" });
//   }
// });


import fileUpload from "express-fileupload";



server.use(fileUpload());

server.post("/get-upload", async (req, res) => {
  try {
    if (!req.files || !req.files.image) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const imageFile = req.files.image;
    // Save the file temporarily
    const tempPath = `./uploads/${imageFile.name}`;
    await imageFile.mv(tempPath);

    // Upload to Cloudinary
    const result = await cloudinary.uploader.upload(tempPath, {
      folder: "codehelp",
    });
    // Clean up: Delete the temporary file
    fs.unlinkSync(tempPath);

    // Respond with the Cloudinary URL
    res.status(200).json({ url: result.secure_url });
  } catch (error) {
    console.error("Error uploading to Cloudinary:", error);
    res.status(500).json({ error: "Failed to upload image" });
  }
});

server.post("/change-password",verifyJWT,(req,res)=>{
    let {currentPassword,newPassword } = req.body;
    
if(!passwordRegex.test(currentPassword) || !passwordRegex.test(newPassword)){
    return res.status(403).json({error : "password should be 6 to 20 characters long with a numeric,1 lowercase and uppercase letters"});
    
}

User.findOne({_id:req.user})
// jo verifyjwt hai usme req user me id rakh rhe hai toh waha se lenge user ko yaha 
.then((user)=>{
    if(user.google_auth){
        return res.status(403).json({error : "you can't change account's password because you logged in through google"})
   }

bcrypt.compare(currentPassword,user.personal_info.password,(err,result)=>{
    if(err){
        return res.status(500).json({error:"some error occured while changing the password,please try again later"})
    }

if(!result){
    return res.status(403).json({error:"Incorrect current password"})
}

bcrypt.hash(newPassword,10,(err,hashed_password)=>{
    User.findOneAndUpdate({_id:req.user},{"personal_info.password":hashed_password})
    .then((u)=>{
        return res.status(200).json({status:'password changed'})
    })
    .catch(err=>{
        return res.status(500).json({error:'some error occured while saving new password,please try again later'})
    })
})

})

})
.catch(err=>{
    console.log(err);
    res.status(500).json({error:"User not found"})
})
})

server.post("/update-profile-img",verifyJWT,(req,res)=>{
    let {url} = req.body;

    User.findOneAndUpdate({_id:req.user},{"personal_info.profile_img":url})
    .then(()=>{
        return res.status(200).json({profile_img:url})
    })
    .catch(err=>{
        return res.status(500).json({error:err.message})
    })
})

server.post("/update-profile",verifyJWT,(req,res)=>{
let {username,bio,social_links} = req.body;
let bioLimit = 150;
if(username.length < 3){
    return res.status(403).json({error:"username should be at least 3 letters long"})

}

if(bio.length > bioLimit){
    return res.status(403).json({error:`Bio should not be more than ${bioLimit} characters`});

}

let socialLinksArr = Object.keys(social_links);
// socialLinksArr ye array hoga yaha 

try{
for(let i=0;i<socialLinksArr.length;i++){
    if(social_links[socialLinksArr[i]].length){
        // kya link hai object me as array me toh keys hai yaha 
        let hostname = new URL(social_links[socialLinksArr[i]]).hostname;
        // yadi url galat hai toh url se le nhi payenge 
        if(!hostname.includes(`${socialLinksArr[i]}.com`) && socialLinksArr[i] !='website'){
            // return some error over here 
            return res.status(403).json({error:`${socialLinksArr[i]} link is invalid. you must enter a full link`})

        }
    }
}
}
catch(err){
    return res.status(500).json({error:"you mst provide full social links with http(s) included"})
}

let updateObj = {
    "personal_info.username": username,
    "personal_info.bio":bio,
    social_links
}

User.findOneAndUpdate({_id:req.user},updateObj,{
runValidators:true
})
.then(()=>{
    return res.status(200).json({username})
})
.catch(err=>{
    if(err.code==11000){
        // if thre is any duplication error by runvalidators 
        return res.status(409).json({error:"username is already taken"})
    }
    return res.status(500).json({error:err.message})
})

})

server.post('/latest-blogs', (req, res) => {

let {page} = req.body;

    const maxLimit = 5;
//     // blog refer kar rha hai blogs collection in mongodb here blog written because we have imported it with the name blog 

    Blog.find({ draft: false })
        .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ publishedAt: -1 })
        .select("blog_id title des banner activity tags publishedAt -_id")
        // skip skips the blog like if page 1 is there then 1-1 0 means no skip if page 2 then maxlimit like 5 mneans to skip 5 blog and from there next 5 blog will come 
       .skip((page-1)* maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        });
});

server.post("/all-latest-blogs-count",(req,res)=>{
    Blog.countDocuments({draft : false})
    .then(count =>{
        return res.status(200).json({totalDocs : count})
    })
    .catch(err =>{
        console.log(err.message);
        return res.status(500).json({error : err.message})
    })
})

server.post("/search-blogs-count",(req,res) =>{
    let {tag,author,query} = req.body;

    let findQuery;
if(tag){
    findQuery =  {tags : tag,draft:false};
}else if(query){
    findQuery = {draft:false , title : new RegExp(query,'i')}
}
else if(author) {
    findQuery = {author,draft:false}
}
    Blog.countDocuments(findQuery)
    .then(count =>{
        return res.status(200).json({totalDocs : count})
    })
    .catch(err =>{
        console.log(err.message);
        return res.status(500).json({error:err.message})
    })
})
    // blog find karo jiska draft false hai and uss blog me populate karo author me jo value jo ki id hai reference hai user ka and uss author ya user id jiss user ka hai uska kya kya chahiye wo de denge mil jayega yaha 
// jo jo fields diya wo hi do and _id mat do yaha 
// as we want the latest blog we will sort it by published at 
// publishedate -1 means sort from recent ones 
// in select we choose the fields we want to select because we dont want the whole data of the blogs here blog_id is the custm id that we have made here 
// {blogs} iska matlab blogs jo mil rha hai usme blogs naam ka key hai jisme array mila hai saara data blogs ka 
// blogs array me object hai blogs ka 

server.post("/search-users" , (req,res)=>{
    
let {query} = req.body;
User.find({"personal_info.username": new RegExp(query,'i')})
.limit(50)
.select("personal_info.fullname personal_info.username personal_info.profile_img -_id")
.then(users =>{
    return res.status(200).json({users})
})
.catch(err =>{
    return res.status(500).json({error:err.message})
})
})

server.post("/get-profile",(req,res)=>{
    let {username} = req.body;
    User.findOne({"personal_info.username" : username})
    .select("-personal_info.password -google_auth -updatedAt -blogs")
    // ye jo minus likhe isko chorke sab de dega 
    // username toh unique hi hai databse me unique karke rakh rhe hai jo ki ui me shhow ho rha hai and uspe click hote hi /user/username karke kiye hue hai ye khulega and le lenge yaha se yaha 
    .then(user =>{
        return res.status(200).json(user)
    })
    .catch(err =>{
        console.log(err);
        return res.status(500).json({erro : err.message})
    })
    // jo username jo bhi daal de toh null yega and phir user ko redirect kar denge 404 page me yaha 

})

server.get("/trending-blogs" , (req,res) =>{
    Blog.find({draft:false})
    .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
    .sort({"activity.total_read" : -1, "activity.total_likes" :-1,"publishedAt" : -1})
    .select("blog_id title publishedAt -_id")
    .limit(5)
    .then(blogs =>{
        return res.status(200).json({blogs})
    })
    // populate se jo author me objectid hai wo hatke usme jo jo diye wo mil jayega yaha 
// here sorting will be done by reads and if reads are same then by likes and if they became same then publishedat will be there from which it will be done here 
// yaha par toh hoga publishedat se kyuki abhi read and like don 0 hai same hai magar aise hoga ki read ke hisab se sorting like ke hisab se sorting ya publishedat se sorting hoga yaha 
// ab yaha limit 5 se 5 milega blogs and blogs ko response me bhej denge jo ki array hoga 

})

server.post("/search-blogs",(req,res)=>{

let {tag,query,author,page,limit,eliminate_blog} = req.body;

let findQuery;

if(tag){
    findQuery =  {tags : tag,draft:false,blog_id:{$ne:eliminate_blog}};
    // yaha qury me jayega ki elminate blog ko chorke baaki saara blog o daalo yaha 
    
}else if(query){
    findQuery = {draft:false , title : new RegExp(query,'i')}
}
// title me se jo search kiye dekhega and i matlab case sensitve nhi hoga and jo query hai yadi jo jo title me hai de dega 
// search hamesha title pe hoga 
else if(author) {
    findQuery = {author,draft:false}
}


let maxLimit = limit ? limit:2;
// yadi limit bheje matlab ye case hai ki jaha imit and tag bheje hai and yadi limit nhi hai toh sirf tag bheje honge and limit 2 lena hai yaha 


Blog.find(findQuery)
 .populate("author", "personal_info.profile_img personal_info.username personal_info.fullname -_id")
        .sort({ publishedAt: -1 })
        .select("blog_id title des banner activity tags publishedAt -_id")
        // skip skips the blog like if page 1 is there then 1-1 0 means no skip if page 2 then maxlimit like 5 mneans to skip 5 blog and from there next 5 blog will come 
    .skip((page-1)*maxLimit)
        .limit(maxLimit)
        .then(blogs => {
            return res.status(200).json({ blogs });
        })
        .catch(err => {
            return res.status(500).json({ error: err.message });
        });
})





server.post('/create-blog',verifyJWT,(req,res)=>{
    // here we do not want that user who didnot signed in use this post request so first we will authenticate the ser who will have access token stored in the session 
// so from frontend we will send access token which will be verified here and first this thing will be done by middleware verifyjwt in which after validaton then the next function which is callback function will run here 
// after the verifytoken this ewill run sayng that the user is valid user whch is signed up 

//    return res.json(req.body)
// {
//     "title": "test title"
//   }
// when we gave this object in request so here in backend we return req.body so this object as it is return was happening 

let authorId = req.user
// here we got user id which was set by middleware 

// from frontend we will send blogstructur object which has everything title etc 

let {title,des,banner,tags,content,draft,id} = req.body;

// draft chek karnege pehle yadi draft hai tab kuch condition check nhi karenge sirf karenge title ko kyuki wo lagega id bhi banayega na isliye and jab draft karenge toh phir hone ke baad ayga mongo me blogs me wo data jaha pe draft true hoga and usr jo kiye usme total post change nhi hoga as wbackendd me waisa likhe hai draft nhi hai toh badho and blog id jo draft wala hai wo ayega array me blog id user ke blog aray me yaha 

if(!title.length){
    return res.status(403).json({error:"you must provide a title"});

}
if(!draft){

    if(!des.length || des.length > 200){
        return res.status(403).json({error:"you must provide blog description under 200 characters"});
    }
    // here we are checking the description andsame thing we have done in frontend also here 
    
    
    if(!banner.length){
        return res.status(403).json({error : "you must provide blog banner to publish it"});
    
    }
    
    // if(content) =>{
    //     blocks:[],
    //     // aise karke editor se object milta hai content naam ka use check karenge ki usme blobks array me data hai ki nhi yaha 
    
    // }
    
    if(!content.blocks.length){
        return res.status(403).json({error: "there must be sme blog content to publish it"});
    
    }
    
    if(!tags.length || tags.length > 10){
    return res.status(403).json({error : "provide tags in order to publish the blog , Maximum 10"});
    
    }
    
}

// here als we are validating in backend the title wheter it is here or not because it is good to do here also not only in frontend 

// so we will convert all the tags into lowercase as user can renter tags same category in different ways like TECH Tech tech all belong to same category but written differently so we will convert all tags in lower case the save to db 

tags = tags.map(tag => tag.toLowerCase());
// by this tags array will not have mutiple entries or tags as Tech TECH tech will be taken or treated differently but here as we converted them ito lowercase now we know they are three same category as because through code we cant directly identify that these three tags are different 

// we need create blog id to store blog data in database infact id we will get from mongodb when we store daa in db but we cant use it as it is private not public so it protect database 

// title ko use karenge and replace karenge usme character ko space me and space ko phir - me kyuki ho nhi sakta url me space yaha 
// trim kiye yadi extra space hua usko trm karne ke liye and nnoid e add kiye hai yaha 

let blog_id = id || title.replace(/[^a-zA-Z0-9]/g,' ').replace(/\s+/g, "-").trim()  + nanoid();

// yadi id hai pehle se toh ye hoga warna naya id banega and phir aage badhega yadi id nhi hua toh naya blog banega yadi id pehle se hai matlab ki edit se aaya hai save hone ko toh naya nhi banega dobara save hoga yaah 

if(id){
Blog.findOneAndUpdate({blog_id},{title,des,banner,content,tags,draft:draft?draft:false})
.then(()=>{
    return res.status(200).json({id:blog_id});
})
.catch(err=>{
    return res.status(500).json({error:"failed to update total posts number"})
})
}else{
    // POST http://localhost:3000/create-blog
// Content-Type: application/json
// Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY3YWYxYzc3ZDg2M2RlNjMwYjIzY2ZkZiIsImlhdCI6MTczOTUyOTMzNX0.j0ak7hl8dR46UvSU5hAflJWeRU1vhqEQv0Z6Qmvw6Rs

// # blank line after the header is necessary 
// # # if given no authorization or no access token then error is coming saying no acces token as beacause token is null and also if token given random which is not valid showing acess token is not valid 


// {
//   "title": "test title",
//   "banner" : "https://example.com/image-url",
//   "des":"this is ashort des",
//   "content" : {
//     "blocks" : [1,2]
//   },
// "tags" : ["tag1","tag2"]
//   }

// test-titlegYP49Z7iqEnZryFPVCP3G ye aaya 

// "title": "test title  @ 3 134 ",
// tab ye ayega test-title-3-134-L24CtJhUg-Av2v0fxaER_

// now we will use this blog id to store blog in our database and this id we will store in our database as mongo id we cant use publicaly for purpose here 


// blogid isliye liye kyuki schema me wo bhi hai jisse store karnge db me yaha 

// object bana rhe hai blog schema ka yaha 

let blog = new Blog({
title,des,banner,content,tags,author : authorId , blog_id,draft: Boolean(draft)
})

// yaha author me mongo wala objectid rakh rha hai ye jisko author me rakh rhe hai and authorid wo wala id hai object id and draft true hog ya false false matlab isko rakhna hai store karna hai and true matlab isko return karna hai 
// yaha draft booleam ke andar draft toh undefined hoga yadi frontend se nhi bheje draft toh boolean draft false dega as undefined false toh boolean draft false dega jisse draft false ho jayega bydefaut and yadi bhejna hua ya change karna hua toh isko bhej denge frontend se yaha yaha 

blog.save().then(blog=>{
    let incrementVal = draft ? 0: 1;
    // User.findOneAndUpdate({_id:authorId},{$inc : {"account_info.total_posts" : incrementVal},$push : {"blogs" : blog._id}})
    // yaha user me total post ahi usko badhana hai toh yadi blog draft nhi karna false hai toh badhadege warna nhi badhayenge and user ko find kar rhe hai jo blog post kiya hai uska user me badhayenge toh usko find kar rhe hai _id jo ki user ka id wo equal ho authorid ye wal ke ye chahiye user and as ye user ka id store kar rhe author me jo ki blogs schema ka hai isliye uska type rakhe objectid wo bhi ref user ka and waise hi jo blog post arenge wo alag se mongo me blogs karke ayega jo ki hoga uska id alag se dega toh uska id ko iss user ke blogs naam ka array me jo ki object id rakega blogs ka ref blogs ka toh jisse pata lag jayega ye user kaun kaun sa blog post kiya hai as uss array me id rahega blog ka id yaha 
// jaise hi user ko find kiye authorid se jo ki frontend se bhejenge and phir usko authorid jisko rakhe hai blogs db me bhi jo ki batayega ye id wala user post kiya hai and phir bogs jo save kiye iska id ko user ka blog array me wo id ko store kar denge jisse pata lag jayega ki ye user kaun kaun sa blog post kiya hai as blog ka alag se db banega jisme sab kuch hoga id etc etc 
// push matlab push karna hai yaha 
User.findOneAndUpdate({_id:authorId},{$inc : {"account_info.total_posts" : incrementVal},$push : {"blogs" : blog._id}})
.then(user =>{
    return res.status(200).json({id:blog.blog_id})
})
// ab yaha jo user return hoga and return karnege wo blog ka id jo ki custom banaye the usko send karenge jo ki blogs ka db me uska schema me store kar liye the thodi na frontend me actual wala bhenjenge id 
.catch(err =>{
    return res.status(500).json({error : "failed to update total posts number"})
})


})

.catch(err =>{
    return res.status(500).json({error : err.message})
})


// {
//     "id": "test-title-3-134-EpNat2GzVwT2GidisFWjw"
//   }


//   POST http://localhost:3000/create-blog
// Content-Type: application/json
// Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY3YWYxYzc3ZDg2M2RlNjMwYjIzY2ZkZiIsImlhdCI6MTczOTUyOTMzNX0.j0ak7hl8dR46UvSU5hAflJWeRU1vhqEQv0Z6Qmvw6Rs

// # blank line after the header is necessary 
// # # if given no authorization or no access token then error is coming saying no acces token as beacause token is null and also if token given random which is not valid showing acess token is not valid 


// {
//   "title": "test title  @ 3 134 ",
//   "banner" : "https://example.com/image-url",
//   "des":"this is ashort des",
//   "content" : {
//     "blocks" : [1,2]
//   },
// "tags" : ["tag1","tag2"]
//   }

// toh jo title bheje wahi id hua and return ho gya yaha 
// ab mongo me dikh rha hai blog me ek blog aa gya hai title hai sab kuch hai usme and author me contain karta hai user ka id object_id and user me jo user kiya ai and uska blogs array euss user ka id object_id aa gya blogs ka and total post 1 se increment ho gya yaha 

}


})

server.post("/get-blog",(req,res)=>{
    let { blog_id ,draft,mode}= req.body;

let incrementVal = mode!='edit'? 1 : 0 ;
// ab yadi 0 hua toh niche wala chal bhi gya toh kuch nhi hoga yaha 

    Blog.findOneAndUpdate({blog_id},{$inc : {"activity.total_reads":incrementVal}})
    .populate("author" , "personal_info.fullname personal_info.username personal_info.profile_img")
    .select("title des content banner activity publishedAt blog_id tags")
    .then(blog=>{
        User.findOneAndUpdate({"personal_info.username":blog.author.personal_info.username} ,{$inc : {"account_info.total_reads":incrementVal}})
        .catch(err=>{
            return res.status(500).json({error:err.message})
        })

        if(blog.draft && !draft){
            return res.status(500).json({error:'you cannot access draft blog'})
        }
        // yaha user blog ka draft dekhega ki true and draft false matlab ki edit wala se request nhi aaya matlab ki draft blog true nhi hai matlab access nhi milega yadi draft true jo ki hoga jab blog ko edit karke kiye honge jo ki sirf jiska hai draft wahi kar sakta ha toh access allow wana normal koi published blog hi edit karna chaha toh blog ka draft false hoga tab bhi access allow hoga yaha 

        return res.status(200).json({blog});
    })

    .catch(err =>{
return res.status(500).json({error:err.message});
    })
})

// yaha blogid bhej diye and phir blog id ko populate kiye sab uch phir popuate karne k baad select kiye and blog ko bhej diye hai blog object ko jisem jo jo sleect kiye hai wo sab bhej denge and findoneupdate se toh update ho hi jayea yaha 
// ab yaha pe user ko khoje blog jiska hai usernaem se uska phir kar liye uska read change ki uss blog jo banaa uska read ko bhi badha diye yaha 

// ab jo blog click hua hai uss blog ka author ka read ko badha denge 
// jo blog return ho rha hai uss blog me jo uska read hoga wo ek kam wala hoga as pehle return kar rha hai phir add kar rhe hai increment kar rha hai 

server.post("/like-blog",verifyJWT,(req,res)=>{
    let user_id = req.user;
    let { _id,islikedByUser} = req.body;
// jo blog user ko bhej rhe hai get blog me jisse wo like dislike karega ad usme _id and blogid dono hai ek mongo db jo kiya and ek khud crezte kiye toh mongo wala yaha bhejke fnd kar rhe hai yaha 

    let incrementVal = !islikedByUser ? 1 : -1;
    Blog.findOneAndUpdate({_id},{$inc:{"activity.total_likes":incrementVal}})
    .then(blog =>{
if(!islikedByUser){
    // islikedby user yadi false tha iska matlab ki islikedbyuser jo hai usko jo false hai ab true toh 1 hoke phir isko true karna hai taaki phir jab ho toh -1 ho yaha 
let like = new Notification({
    type:"like",
    blog:_id,
    notification_for:blog.author,
    user:user_id

})
// notification me jaise a ike kiya toh user me jo kiya uska id and notification for me jiska blog ko kiya uska id yaha 

like.save().then(notification =>{
    return res.status(200).json({liked_by_user:true})
})

}else{
    // isliked wala true tha pehle toh jarur ye vclick k=hua matla dislike th jo notification wala save hai usko hatao taaki like icon na dikhe yaha 
    Notification.findOneAndDelete({user:user_id,blog:_id,type:"like"})
.then(data =>{
    return res.status(200).json({liked_by_user:false})
})
.catch(err=>{
    return res.status(500).json({error:err.message})
})
}
    })
})

server.post("/isliked-by-user",verifyJWT,(req,res)=>{

    let user_id = req.user;
    let{_id} =req.body;

Notification.exists({user:user_id,type:"like",blog:_id})
// user_id wo user jo like kiya hai ki nhi yaha 
.then(result =>{
    return res.status(200).json({result}) 
    // result me true ya false jayega yaha 

})
.catch(err =>{
    return res.status(500).json({error:err.message})
})

})

server.post("/add-comment",verifyJWT,(req,res)=>{
    let user_id = req.user;
    let {_id,comment,blog_author,replying_to,notification_id} = req.body;
    if(!comment.length){
        return res.status(403).json({error:'writing something to leave a comment...'})

    }

    //creating a comment doc

    let commentObj ={
        blog_id : _id,blog_author,comment,commented_by:user_id 
    }

    if(replying_to){
        commentObj.parent = replying_to;
        commentObj.isReply=true;
    }
// jo comment rep wala hoga usme arent me id hoga 

   new Comment(commentObj).save().then(async commentFile=>{

let {comment,commentedAt,children } =commentFile;

Blog.findOneAndUpdate({_id},{$push:{"comments": commentFile._id},$inc:{"activity.total_comments":1,"activity.total_parent_comments" :replying_to? 0:1},})
// jo blog hoga usme comments array me jo comment hai banaye document uska id ko tore karenge yaha 
.then(blog=>{
    console.log('New comment Created')
});

let notificationObj ={
    type : replying_to?"reply":"comment",
    blog:_id,
    notification_for:blog_author,
    user:user_id,
    comment:commentFile._id
}

if(replying_to){
    notificationObj.replied_on_comment = replying_to;

    await Comment.findOneAndUpdate({_id:replying_to},{$push:{children:commentFile._id}})
    // comment jo parent wala hai usme child wala denge comment id 
    .then(replyingToCommentDoc =>{notificationObj.notification_for= replyingToCommentDoc.commented_by})

if(notification_id){
    Notification.findOneAndUpdate({_id:notification_id},{reply:commentFile._id})
    // jo comment save kiye uska id notification jispe comment kiye uske reply me daal rhe hai yaha 
    .then(notification=>console.log('notification updated'))
}


}

new Notification(notificationObj).save().then(notification=>console.log('new notification created'));

return res.status(200).json({
    comment,commentedAt,_id:commentFile._id,user_id,children
})

    })

})

server.post("/get-blog-comments",(req,res)=>{
    let {blog_id,skip} = req.body;
    let maxLimit = 5;
    Comment.find({blog_id,isReply:false})
    .populate("commented_by","personal_info.username personal_info.fullname personal_info.profile_img")
    .skip(skip)
    .limit(maxLimit)
    .sort({
        'commentedAt' : -1
    })
    .then(comment =>{
        return res.status(200).json(comment);

    })
    .catch(err=>{
        console.log(err.message);
        return res.status(500).json({error:err.message})
    })
})

server.post("/get-replies",(req,res)=>{
    let {_id,skip} = req.body;
    let maxLimit = 5;
    Comment.findOne({_id})
    .populate({
        path:"children",
        options:{
limit:maxLimit,
skip:skip,
sort:{'commentedAt' : -1}
        },
        populate:{
path:'commented_by',
select:"personal_info.profile_img personal_info.fullname perona_info.username"
        },
        select:"-blog_id -updatedAt"
    })
    .select("children")
    .then(doc=>{
        return res.status(200).json({replies:doc.children})
    })
    .catch(err =>{
        return res.status(500).json({error:err.message})
    })
})

const deleteComments = (_id) =>{
    Comment.findOneAndDelete({_id})
    .then(comment=>{
if(comment.parent){
    // yadi comment me parent hai iska matchMedia;ab ye children hai reply hai jisklodelte kar rhe hai yaha 
   Comment.findOneAndUpdate({_id:comment.parent},{$pull:{children:_id}}) 
// parent khojke usme children array e ye comment jo reply hai usko hata diye yaha 
.then(data => console.log('comment delete from parent'))
.catch(err =>console.log(err));
}
Notification.findOneAndDelete({comment:_id}).then(notification =>console.log('comment notification deleted'))
Notification.findOneAndUpdate({reply:_id},{$unset:{reply:1}}).then(notification =>console.log('reply notification deleted'))

Blog.findOneAndUpdate({_id:comment.blog_id},{$pull:{comments:_id},$inc:{"activity.total_comments":-1},"activity.total_parent_comments":comment.parent?0:-1})
.then(blog=>{
    if(comment.children.length){
        // yadi parent ka reply hai toh usko bhi delte karna hai yaha 
        comment.children.map(replies=>{
            deleteComments(replies)
        })
    }
})
    })
    .catch(err=>{
        console.log(err.message);
    })
}

server.post("/delete-comment",verifyJWT,(req,res)=>{
    let user_id = req.user;
    let {_id} = req.body;
    // ye id comment ka id hoga and iska children ko bhi delte kar denge yaha 
    Comment.findOne({_id})
    .then(comment=>{
        if(user_id == comment.commented_by || user_id == comment.blog_author){
deleteComments(_id);
// ye function me loop chaleg jo children and phir children ka children dekhke delete karega yaha 
return res.status(200).json({status:'done'});
        }else{
            return res.status(403).json({error:"you can not delete this comment"})
        }
    })
})

server.get("/new-notification",verifyJWT,(req,res)=>{
    let user_id = req.user;

    Notification.exists({notification_for:user_id,seen:false,user:{$ne:user_id}})
// yadi user khud ka hi comment me kiye hai comment wo notification me nhi dikhayenge isliye isko not include kiye ki user id ke equal user hua matlab yahi khud ka bog m kiya hai toh nhi hoga and baaki wala jaha aisa nhi hai matlab koi aur user usko kiya hai toh wo dikhega and wo seen false bhi hona chahiye yaha 
   .then(result=>{
    if(result){
        return res.status(200).json({new_notification_available:true})
    }
    else{
        return res.status(200).json({new_notification_available:false})
    }

   })
   .catch(err=>{
    console.log(err.message);
    return res.status(500).json({error:err.message})

   })
})

server.post("/notifications",verifyJWT,(req,res)=>{
    let user_id=req.user;
    let {page, filter,deletedDocCount} = req.body;
    let maxLimit =10;

    let findQuery = {notification_for:user_id,user:{$ne:user_id}};

    let skipDocs = (page-1) * maxLimit;
if(filter != 'all'){
    findQuery.type=filter;
}

if(deletedDocCount){
    skipDocs-=deletedDocCount;
    // yadi 4 delete kiye hai notification toh skip 
}

Notification.find(findQuery)
.skip(skipDocs)
.limit(maxLimit)
.populate("blog","title blog_id")
.populate("user","personal_info.fullname personal_info.username personal_info.profile_img")
.populate("comment","comment")
.populate("replied_on_comment","comment")
.populate("reply","comment")
.sort({createdAt:-1})
.select("createdAt type seen reply")
.then(notifications=>{
    Notification.updateMany(findQuery,{seen:true})
    .skip(skipDocs)
.limit(maxLimit)
.then(()=>{console.log('notification seen')});
    return res.status(200).json({notifications});
})
.catch(err=>{
    console.log(err.message);
    return res.status(500).json({error:err.message});

})

})

server.post("/all-notifications-count",verifyJWT,(req,res)=>{
    let user_id = req.user;

    let {filter} = req.body;
    let findQuery = {notification_for:user_id,user:{$ne:user_id}}

    if(filter != 'all'){
        findQuery.type=filter;

    }
    Notification.countDocuments(findQuery)
    .then(count =>{
        return res.status(200).json({totalDocs:count})

    })
.catch(err=>{
    return res.status(500).json({error:err.message})
})

})

server.post("/user-written-blogs",verifyJWT,(req,res)=>{
    let user_id = req.user;
    let {page,draft,query,deletedDocCount } = req.body;

    let maxLimit =5;
    let skipDocs=(page-1) * maxLimit;

    if(deletedDocCount){
        skipDocs -=deletedDocCount;
    }

    Blog.find({author:user_id,draft,title:new RegExp(query,'i')})
    .skip(skipDocs)
    .limit(maxLimit)
    .sort({publishedAt:-1})
    .select("title banner publishedAt blog_id activity des draft -_id")
.then(blogs=>{
    return res.status(200).json({blogs})

})
.catch(err=>{
    return res.status(500).json({error:err.message});
})
})

server.post("/user-written-blogs-count",verifyJWT,(req,res)=>{
    let user_id=req.user;
    let {draft,query} = req.body;
    Blog.countDocuments({author:user_id,draft,title: new RegExp(query,'i')})
    .then(count=>{
        return res.status(200).json({totalDocs:count})
    })
    .catch(err=>{
        console.log(err.message);
        return res.status(500).json({error:err.message});
    })
})

server.post("/delete-blog",verifyJWT,(req,res) =>{
    let user_id = req.user;
    let {blog_id} = req.body;

Blog.findOneAndDelete({blog_id})
.then(blog=>{
    Notification.deleteMany({blog:blog._id}).then(data=>console.log('notifications deleted'));
    Comment.deleteMany({blog_id:blog._id}).then(data=>console.log('comments deleted'));

const incValue = blog.draft ? 0 : -1;

User.findOneAndUpdate(
  { _id: user_id },
  {
    $pull: { blog: blog._id },
    $inc: { "account_info.total_post": incValue }
  }
)
    .then(user=>console.log('blog deleted'));

    return res.status(200).json({status:'done'});

})
.catch(err=>{
    return res.status(500).json({error:err.message})
})

})

server.listen(PORT,()=>{
    console.log('listening on port -> ' + PORT);

})

