// Connection to MongoDB
import mongoose from 'mongoose';

const connectDB = async () => {
  console.log('MongoDB connection with retry');
  try{
  await mongoose.connect(process.env.DATABASE_URL, {
   
  })
    
}catch(err) {
  console.log('MongoDB connection unsuccessful, retry after 5 seconds.');
  setTimeout(connectDB, 5000);
  console.log(err)
  };
}

export default connectDB