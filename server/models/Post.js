const mongoose = require('mongoose')

const Schema= mongoose.Schema;
const postschema= new Schema({
    title:{
        type:String,
        required:true
    },
    body:{
        type:String,
        required:true
    },
    createAT:{
     type:Date,
     default: Date.now   
    },
    updateAT:{
        type:Date,
        default: Date.now   
       },
});
module.exports=mongoose.model('post',postschema);