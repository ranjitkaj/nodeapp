const e = require("express");
const express = require("express")
const bcrypt = require("bcrypt");
const passport = require('passport');
const path = require("path");
const multer = require('multer');
const bodyparser = require("body-parser");
const session = require("express-session");
const nodemailer = require('nodemailer');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const app = express();
port = process.env.PORT || 3000;
// const User = require("./database")

app.listen(port , ()=>{
    console.log(`app is running on port ${port}`)
})

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(bodyparser.json());


app.use(session({
  secret: "user_id",  
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 5 * 60 * 1000 }  
}));

let users = [];


const mongoose = require("mongoose");
const { match } = require("assert");
mongoose.connect("mongodb+srv://ranjit:ranjit@ranjit.ed26i.mongodb.net/?retryWrites=true&w=majority&appName=ranjit").then(()=>{
    console.log("database connected");
}).catch((e) => {
    console.log(e);
})
const Schema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    cpassword: String,
    role:{ type: String,  default: "user"},
    date:{type: Date, default: Date.now},

 })
const Usermodel = mongoose.model("User" , Schema);

const adminSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String,
    cpassword: String,
    role : { type: String,  default: "admin"},
    })

const Adminmodel = mongoose.model("Admin" , adminSchema);

app.use(express.static(path.join(__dirname, "public")));


const storage = multer.diskStorage({
    destination: './uploads/', 
    filename: function (req, file, cb) {
      cb(null, file.fieldname + '-' + Date.now() + path.extname(file.originalname));
    }
  });

  const upload = multer({
    storage: storage,
    limits: { fileSize: 10000000 }, 
    fileFilter: function (req, file, cb) {
     
      checkFileType(file, cb);
    }
  }).single('file');  
  function checkFileType(file, cb) {
    
    const filetypes = /jpeg|jpg|png|pdf|doc|docx|txt/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
  
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb('Error: Invalid file type!');
    }
  }
  

  app.post('/upload', (req, res) => {
    upload(req, res, (err) => {
      if (err) {
        res.send('Error: ' + err);
      } else {
        if (req.file == undefined) {
          res.send('Error: No File Selected!');
        } else {
          res.send(`File uploaded: ${req.file.filename}`);
        }
      }
    });
  });

  app.get("/upload", (req, res) => {
    res.render("upload");
  })



// module.exports = Usermodel;

// ########   created in sync way   #######

// createmp = new Usermodel({
//     name: "Mukesh kumar",
//     email: "mk5956@123",
//     password: "mk59123",
//     mobile: 5345631456,
//     address: "Saharsha",
//     salary: 15000
// }).save().then(()=>{
//     console.log("saved");

// })


// ###### created in async way #########

// createemp = async() => {
//     try {
//         const createemp = new Usermodel({
//             name: "Sanjit kumar",
//             email: "sk5956@123",
//             password: "sanjeet9123",
//             mobile: 5345631456,
//             address: "Gaya",
//             salary: 20000
//         })
//         const emd = await createemp.save();
//         console.log(emd)
//     } catch (error) {
//         console.log(error)
//     }
//     }
//     createemp();



// ##########  Read data from database  ##########


// readData = async()=>{
//     try {
//         const data = await Usermodel.find();
//         console.log(data);
//     }
//     catch (error) {
//         console.log(error)
//     }
// }
// readData();


// ##########  Read data from database with condition   ##########

// readData = async()=>{
//     try {
//         const data = await Usermodel.find( {salary:{$gt:15000}}).select({name:2, email:1}).limit(15);
//         console.log(data);
//     }
//     catch (error) {
//         console.log(error)
//     }
// }
// readData();

// ##########  Read data from database with condition $and oprater  ##########

// readData = async()=>{
//     try {
//         const data = await Usermodel.find( { $and:[{name:"Sujeet kumar"},{salary:{$gt:14000}}]});
//         console.log(data);
//     }
//     catch (error) {
//         console.log(error)
//     }
// }
// readData();



// updateData = async(name)=>{
//     try {
//         const data = await Usermodel.updateOne({name:name});
//         console.log(data);
//     }
//     catch (error) {
//         console.log(error)
//     }
// }
// updateData("ranjit kumar");

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000);
}

const otp = generateOTP();

console.log(otp);


app.use(express.static("public"));
app.use(express.json());
app.use(express.urlencoded({extended:false}))

app.get("/",async(req,res)=>{
    const users = await Usermodel.find({});
    res.render("home",{
        title:"this is homepage",
        users:users
    })
  
})

// const ADMIN_USER = 'admin@xyz.com';
// const ADMIN_PASS = 'admin';

app.get("/aregister", (req, res) => {
    res.render("aregister");
})

app.post("/aregister",async (req, res) => {
  const email = req.body.email;
  const match = await Adminmodel.findOne({email:email});
  if(match){
      res.send("you are already registerd. please login");
  }
  else{
  cpassword = req.body.cpassword;
  password = req.body.password;
  if(password!=cpassword){
      res.send("password not match");
  }
  else{
      const salt = await bcrypt.genSalt(10);
      const hashpassword = await bcrypt.hash(password,salt);
      const admin = new Adminmodel({
          name: req.body.name,
          email: req.body.email,
          password: hashpassword
      })
      const adminsave = await admin.save();
      res.redirect("/aregister");
  }
}
})
 

      


app.get("/admin", (req, res) => {
    res.render("admin");
})

app.post("/admin", async(req, res) => {
        const email = req.body.email;
        const admin = await Adminmodel.findOne({email});
        if (!email) {
        return res.status(400).send('Email is required');
      }
      const otp = generateOTP();
      req.session.otp = otp;
      req.session.email = email;
      sendOTPEmail(email, otp); 
    if(admin){
        if(await bcrypt.compare(req.body.password, admin.password)){
            req.session.admin_id = admin._id;
            console.log(req.session.admin_id);
            console.log(admin._id);
            res.render("verify")
            
        }
        else{
            res.send("password not match");
        }
        }
    else{
        res.send("Admin not found");
        }

});

app.get("/verify", (req, res) => {
  if (!req.session.admin_id) {
    res.redirect("/admin");
    return;
  }
    res.render("verify");
})


app.post("/verify", async (req, res) => {
  const { otp } = req.body;
        if (!req.session.otp || !req.session.email) {
        return res.status(400).send('No OTP found in session');
      }
        if (parseInt(req.session.otp) === parseInt(otp)) {
        req.session.otp = null;
        if (!req.session.admin_id) {
          res.redirect("/admin");
          return;
      }
      else {
        const users = await Usermodel.find({});
        const files = await Adminmodel.find({});
        res.render("index", {
            title: "this is admin page",
            users: users,
            files: files   
      })}
      } else {
        res.status(400).send('Invalid OTP');
      }
   
})

   

app.post("/register",async(req,res)=>{
    const email = req.body.email;
    const match = await Usermodel.findOne({email:email});
    if(match){
        res.send("you are already registerd. please login");
    }
    else{
    cpassword = req.body.cpassword;
    password = req.body.password;
    if(password!=cpassword){
        res.send("password not match");
    }
    else{
        const salt = await bcrypt.genSalt(10);
        const hashpassword = await bcrypt.hash(password,salt);
        const user = new Usermodel({
            name: req.body.name,
            email: req.body.email,
            cpassword: hashpassword
        })
        const usersave = await user.save();
        res.redirect("/register");
    }
}
})
   

app.get("/register",(req,res)=>{
    res.render("register");
})

app.get("/edit/:id",async(req,res)=>{
    const id = req.params.id;
    const user = await Usermodel.findById(id);
    res.render("edit",{
        user:user
    })
})


app.post("/update/:id",async(req,res)=>{
    const id = req.params.id;
    const user = new Usermodel({ 
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
  })
  const usersave = await user.save();
  res.redirect("/admin");
})
    

  

app.get("/delete/:id",async(req,res)=>{
    const id = req.params.id;
    const user = await Usermodel.findByIdAndDelete(id);
    res.redirect("/admin");
})

app.get("/login",(req,res)=>{
    res.render("login");
})


app.post("/login",async(req,res)=>{
    const email = req.body.email;
    const user = await Usermodel.findOne({email});
        if (!email) {
          return res.status(400).send('Email is required');
        }
        const otp = generateOTP();
        req.session.otp = otp;
        req.session.email = email;
        sendOTPEmail(email, otp); 
    if(user){
        if(await bcrypt.compare(req.body.password, user.cpassword)){
            req.session.user_id = user._id;
            req.session.name = user.name;
            console.log(req.session.user_id);
            console.log(user._id);
            res.render("verifyotp")
            
        }
        else{
            res.send("password not match");
        }
    }
    else{
        res.send("user not found");
    }
})


app.get("/logout",(req,res)=>{
    req.session.destroy();
    res.redirect("/login");
})


app.get("/dashboard",(req,res)=>{
    if (!req.session.user_id) {
        res.redirect("/login");
    }
    else{
        res.render("dashboard");

    }
})


  
  // Set up the Nodemailer transporter
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'ranjitkajraitha@gmail.com',
      pass: 'shdp iwty fkow yyqc'
    }
  });

  function sendOTPEmail(email, otp) {
    const mailOptions = {
      from: 'your-email@gmail.com',
      to: email,
      subject: 'Your OTP Code',
      text: `Your OTP code is ${otp}`
    };
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.log(error);
        } else {
          console.log('Email sent: ' + info.response);
        }
      });
    }
      app.post('/verify-otp', (req, res) => {
        const { otp } = req.body;
        if (!req.session.otp || !req.session.email) {
        return res.status(400).send('No OTP found in session');
      }
        if (parseInt(req.session.otp) === parseInt(otp)) {
        req.session.otp = null;
        res.render("dashboard", { name: req.session.name });
      } else {
        res.status(400).send('Invalid OTP');
      }
});

app.get("/download/:filename", (req, res) => {
  const filename = req.params.filename;
  const filePath = path.join(__dirname, 'files', filename);
  res.download(filePath);
})

app.use(passport.initialize());
app.use(passport.session());

// Serialize and deserialize user (stores user info in the session)
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new GoogleStrategy({
  clientID: '717128146880-pe4hraoktato1f64pfnf6rft74dsthh0.apps.googleusercontent.com',
  clientSecret: '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',
  callbackURL: 'https://nodeapp-v9bf.onrender.com/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  // Handle the profile and create/store user in your database
  let user = users.find(u => u.id === profile.id) || {
      id: profile.id,
      name: profile.displayName,
      provider: 'google'
  };
  users.push(user);
  return done(null, user);
}));

// Passport Facebook OAuth strategy
passport.use(new FacebookStrategy({
  clientID: '885744719690339',
  clientSecret: '1ec197be4f8c6758396fd452bd134847',
  callbackURL: 'https://nodeapp-v9bf.onrender.com/auth/facebook/callback',
  profileFields: ['id', 'displayName', 'email']
}, (accessToken, refreshToken, profile, done) => {
  // Handle the profile and create/store user in your database
  let user = users.find(u => u.id === profile.id) || {
      id: profile.id,
      name: profile.displayName,
      provider: 'facebook'
  };
  users.push(user);
  return done(null, user);
}));

app.get('/auth/google', passport.authenticate('google', { scope: ['profile'] }));

// Google OAuth callback route
app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        // Successful login
        res.redirect('/profile');
    }
);

// Facebook authentication route
app.get('/auth/facebook', passport.authenticate('facebook'));

// Facebook OAuth callback route
app.get('/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/' }),
    (req, res) => {
        // Successful login
        res.redirect('/profile');
    }
);
app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) {
      return res.redirect('/');
  }
  res.render('dashboard', { name: req.user.name });
  // res.send(`<h1>Profile</h1><p>Welcome ${req.user.name}</p><a href="/logout">Logout</a>`);
});

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
      res.redirect('/dashboard');
  }
);

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/' }),
  (req, res) => {
      res.redirect('/dashboard');
  }
);
