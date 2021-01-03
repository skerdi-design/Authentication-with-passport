const express = require("express");
const app = express();
const bcrypt = require("bcrypt");
const session = require('express-session');
const passport = require("passport");
const flash = require("express-flash");
const LocalStrategy = require("passport-local").Strategy;

const users = [];



initialize(passport,(email)=>{
    return users.find(user=> user.email === email);
},(id)=>{
    return users.find(user=> user.id === id);
});

function initialize (passport,getUserByEmail,getUserById) {
    async function authUser(email,password,done) {
        //the passport package will return the username and password pased by the user here
        const user = getUserByEmail(email);
        console.log(user)
        if(user === undefined){
            return done(null,false,{mesage:'there is no user with that email'});
        }
        console.log(password,user.password);
        try {
            if(await bcrypt.compare(password, user.password)){
                return done(null,user);
            }else{
                return done(null,false,{mesage:'there is no user with that password'});
            }
        } catch (e) {
            return done(e);
        }
    }

    passport.use(new LocalStrategy({ usernameField:'email' },authUser));
    passport.serializeUser((user,done) =>done(null,user.id));//saves user.id in the session
    passport.deserializeUser((id,done) =>{ 
        return done(null,getUserById(id))
     });
}


app.set('view-engine','ejs');
app.use(express.urlencoded({extended: false}));//being able to acces the info from the form
app.use(flash());

app.use(session({
    secret:'secret',//will put later to dotenv file
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize());
app.use(passport.session());

app.get('/',checkAuth,(req,res)=>{ 
    //console.log(req.session);// for debuging
    res.render('home.ejs',({name:'skerdi'}));
});

app.get('/register',(req,res)=>{
    res.render("register.ejs");
})

app.get('/login',(req,res)=>{
    res.render("login.ejs");
})

app.post('/register',async(req,res)=>{
    try{
        const hashedPass = await bcrypt.hash(req.body.password,10);
        users.push({
            id:Date.now().toString(),
            name:req.body.name,
            email:req.body.email,
            password:hashedPass
        });
        res.redirect('/login');
    }catch (e){
        res.redirect("/register");
        console.log(e);
    }
    console.log(users);
})
app.post('/login', passport.authenticate('local',{
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash:true,
}));

const PORT = process.env.PORT || 3000;
app.listen(PORT,()=>console.log(`server starting at port ${PORT}!`));

function checkAuth (req,res,next){
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect('/login');
}