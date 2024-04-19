const express = require('express');
 const router= express.Router();
  const post=require('../models/Post');
  const User=require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Post = require('../models/Post');

  const adminlayout = '../views/layouts/admin';
  const JwtSecret = process.env.JWT_SECRET;

  const authMiddleware = (req,res,next)=>{
    const token = req.cookies.token;

    if (!token){
      return res.status(401).json({message :'unauthorized'});
    }
    try{
      const decoded = jwt.verify(token,JwtSecret);
      req.userId = decoded.userId;
      next();
    }catch(error){
      res.status(401).json({message:'unauthorized'})
    }
  }



  router.get('/admin',async (req, res)=>{
      try{
        const locals={
          title:"admin",
          description:"simple blog about ejs and mongodb"
         }
       res.render('admin/index',{locals,layout:adminlayout});
      }catch(error){
      console.log(error);
      }
  });



//   router.post('/admin',async (req, res)=>{
//     try{
//       const {username,password}= req.body;
//       console.log(req.body)
//        res.redirect('/admin')
//     }catch(error){
//     console.log(error);
//     }
// });



// router.post('/register',async (req, res)=>{
//   try{
//     const {username,password}= req.body;
  
//   }catch(error){
//   console.log(error);
//   }
// });



  router.post('/admin',async (req, res)=>{   
      try{
      const {username, password} = req.body;

      const user = await User.findOne({username});
      if (!user){
        return res.status(401).json({message : 'invalid username'})
      }
      const ispasswordvalid = await bcrypt.compare(password, user.password);
      if (ispasswordvalid){
        return res.status(401).json({message :'invalid credentials'})
      }
const token = jwt.sign({userId: user._id},JwtSecret)
res.cookie('token',token,{httpOnly:true});
res.redirect('/dashboard');
      }
           catch(error){
            console.log(error);
            };
                });






router.get('/dashboard',authMiddleware, async (req, res)=>{
  try{
    const locals={
      title:'dashboard',
      description:'simple blog created'
    }
    const data = await post.findOne();
    res.render('admin/dashboard',{
      locals,
      data
  });
} catch(error){

}
});

router.post('/register',async (req, res)=>{   
try{
const {username, password} = req.body;
// const hashedpassword  = await bcrypt.hash(password, 10);
try{
const user = await User.create({username, password})
 res.status(201).json({message:'user created',user});
}
catch(error){
if (error.code===11000){
   res.status(409).json({message:'user already created'});
}
else{
   res.status(500).json ({message:'internal server eror'})
}
}
}
catch(error){
console.log(error);
}
});

router.get('/add-post',authMiddleware, async (req, res)=>{
  try{
    const locals={
      title:'add-post',
      description:'simple blog created'
    }
    const data = await post.findOne();
    res.render('admin/add-post',{
      locals,
      layout:adminlayout
  });
} catch(error){

}
});

router.post('/add-post',authMiddleware, async (req, res)=>{
  try{
    
try {
  const newpost = new Post({
    title:req.body.title,
    body:req.body.body

  });
  await Post.create(newpost);
  res.redirect('/dashboard');
} catch (error) {
}   
} catch(error){
}
});






  module.exports=router;