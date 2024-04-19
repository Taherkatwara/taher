const express = require('express');
 const router= express.Router();
  const post=require('../models/Post');

 router.get('',async (req, res)=>{

try{
  const locals={
    title:"nodejs blog",
    description:"simple blog about ejs and mongodb"
   }

let perpage=10;
let page = req.query.page || 1;

const data = await post.aggregate([{ $sort :{createdAT:-1}}])
.skip(perpage*page -perpage)
.limit(perpage)
.exec();

const count =await post.count();
const nextpage = parseInt(page)+1;
const hasnextpage = nextpage<= Math.ceil(count/perpage);




res.render('index',{
  locals,
  data,
  current:page,
  nextpage:hasnextpage? nextpage:null
});
}catch(error){
console.log(error);
}




  // res.render("index",{locals});
 });







//  router.get('',async (req, res)=>{
//   const locals={
//    title:"nodejs blog",
//    description:"simple blog about ejs and mongodb"
//   }
  
//   try{
//   const data = await post.find();
//   res.render('index',{locals,data});
//   }catch(error){
//   console.log(error);
//   }
  
  
  
  
//     res.render("index",{locals});
//    });
  



// function insertpostdata(){
//   post.insertMany([
//     {
//       title:"building  blog",
//       body:"this is the body"
//     },
//   ])
// }

// insertpostdata();



router.get('/post/:id',async (req, res)=>{
   
    try{    
let slug = req.params.id;

    const data = await post.findById({_id:slug});

    const locals={
      title:"try blog",
      description:"simple blog about ejs and mongodb"
     }
     



    res.render('post',{locals,data});
    }catch(error){
    console.log(error);
    }
  });
  

 router.post('/search',async (req, res)=>{
  try{
    const locals={
      title:"search",
      description:"simple blog about ejs and mongodb"
     }
     let serachterm= req.body.serachterm;
const searchNoSpecialChar = serachterm.replace(/[^a-zA-Z0-9]/g,"")


  const data = await post.find({
    $or:[
      {title:{$regrex: new RegExp(searchNoSpecialChar,'i')}},
      {body:{$regrex: new RegExp(searchNoSpecialChar,'i')}}
    ]
  });
  res.render("search",{
    data,
    locals
  });
  }catch(error){
  console.log(error);
  }
});










 router.get('/about',(req, res)=>{
    res.render("about");
   });

 module.exports=router;