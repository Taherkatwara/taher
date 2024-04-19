// const mongoose = require('mongoose');
// const connectDB = async () => {
  
//   try {
//     mongoose.set('strictQuery', false);
//     const conn = await mongoose.connect(process.env.MONGODB_URL);
//     console.log(`Database Connected: ${conn.connection.host}`);
//   } catch (error) {
//     console.log(error);
//   }

// }

// module.exports = connectDB;
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    mongoose.set('strictQuery', false);
    console.log('Connecting to MongoDB with URL:', process.env.MONGODB_URL);
    const conn = await mongoose.connect(process.env.MONGODB_URL);
    console.log(`Database Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('MongoDB connection error:', error);
    throw error;
  }
};

module.exports = connectDB;
