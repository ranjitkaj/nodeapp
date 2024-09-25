const express = require("express");
const app = express();
port = process.env.PORT || 3000;

app.listen(port , ()=>{
    console.log(`app is running on port ${port}`)
})

app.set("view engine","ejs");
app.use(express.urlencoded({extended:false}))


const mongoose = require("mongoose");
mongoose.connect("mongodb+srv://ranjit:ranjit@ranjit.ed26i.mongodb.net/?retryWrites=true&w=majority&appName=ranjit").then(()=>{
    console.log("database connected");
}).catch((e) => {
    console.log(e);
})
const Schema = new mongoose.Schema({
    name:String,
    email:String,
    password:String,
    cpassword:String,
    date:{type: Date, default: Date.now},
    address: String,
    gender: String

})
const Usermodel = mongoose.model("User" , Schema);
module.exports = Usermodel;


app.get("/",(req,res)=>{
    res.send(register);
})

app.post("/",async(req,res)=>{
    
    const {name,email,cpassword, date, address}=req.body;
    const newuser = new Usermodel({name, email, cpassword, date,address});
    const usersave = await newuser.save();
    console.log(`usersave ${usersave}`);
    res.redirect("/");

})
