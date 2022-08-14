import jwt from 'jsonwebtoken';
import userModel from '../models/User.js';

var checkUserAuth=async(req,res,next)=>{
    let token;
    const {authorization}=req.headers;
    if(authorization && authorization.startsWith('Bearer')){
        try {
            //Get token from headers
            token=authorization.split(' ')[1];
            // console.log("Token from Headers: ", token);
            // console.log("Authorization: ", authorization);

            //Verify Token
            const {userID}=jwt.verify(token,process.env.JWT_SECRET_KEY);
            // console.log("userID: ",userID);

            // Get User from Token

            req.user=await userModel.findById(userID).select('-password');
            // console.log("REQ USER: ",req.user);
            next()
            
        } catch (error) {
            console.log(error);
            res.status(401).send({"status":"failed","messege":"Unauthorized User"});
        }
    }
    if(!token){
        res.status(401).send({"status":"failed", "messege":"Unathorized User, No token"});
    }
}

export default checkUserAuth;