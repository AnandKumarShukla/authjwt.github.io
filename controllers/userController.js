import userModel from '../models/User.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import transporter from '../config/emailConfig.js';
import nodemailer from 'nodemailer';

class userController{
    static userRegistration=async(req,res)=>{
        const {name,email,password,password_confirmation,tc}=req.body;
        const user=await userModel.findOne({email:email});
        if(user){
            res.send({"status":"failed", "messege":"Already user exist"});
        }else{
            if(name && email && password && password_confirmation && tc){
                if(password === password_confirmation){
                    try {
                        const salt=await bcrypt.genSalt(10);
                        const hashPassword=await bcrypt.hash(password,salt);
                        const doc= new userModel({
                            name:name,
                            email:email,
                            password:hashPassword,
                            tc:tc
                        })
                        const result=await doc.save();
                        // res.status(200).send(result);
                        // Genrating JWT Token
                        const saved_user=await userModel.findOne({email:email}); 
                        const token=jwt.sign({userID: saved_user._id},process.env.JWT_SECRET_KEY,{expiresIn:'5d'});


                        res.status(201).send({"status":"success", "messege":"Registration completed Successfully","token":token});
                        
                    } catch (error) {
                        res.send({"status":"failed", "messege":"Unable to Register"});
                    }
                }else{
                    res.send({"status":"failed", "messege":"Password and Password Confirmation doesn't match"});
                }
            }else{
                res.send({"status":"failed", "messege":"All fields are required"});
            }
        }
    }

    static userLogin=async(req,res)=>{
        try {
            const {email,password}=req.body;
            if(email && password){
                const user=await userModel.findOne({email:email});
                if(user !=null){
                    const isMatch=await bcrypt.compare(password,user.password);
                    if(email === user.email && isMatch){
                        // Genrate JWT token
                        const token=jwt.sign({userID:user._id},process.env.JWT_SECRET_KEY, {expiresIn: '5d'})
                        res.status(200).send({"status":"success","messege":"Welcome to GeekShop", "token":token});
                    }else{
                        res.send({"status":"failed","messege":"Your account or password is incorrect"})
                    }

                }else{
                    res.send({"status":"failed","messege":"You have not register yet"});
                }

            }else{
                res.send({"status":"failed", "messege":"All fields are required"});
            }
            
        } catch (error) {
            console.log(error);
            res.send({"status":"failed","messege":"Unable to Login"});

        }
    }

    static changeUserPassword=async(req,res)=>{
        const {password,password_confirmation}=req.body;
        if(password && password_confirmation){
            if(password !== password_confirmation){
                res.send({"status":"failed", "message":"Password doesn't match with confirmation Password"});
            }else{
                const salt=await bcrypt.genSalt(10);
                const newHashPassword=await bcrypt.hash(password,salt);
                // console.log("REQ USER: ",req.user._id);
                await userModel.findByIdAndUpdate(req.user._id, {$set: {password:newHashPassword}});
                res.status(201).send({"status":"success", "messege":"Password Change successfully "});

            }

        }else{
            res.send({"status":"failed", "messege":"All fields are required"})
        }  
       
    }

    static loggedUser= async(req,res)=>{
        res.send({"user":req.user});
    }


    static sendUserPasswordResetEmail=async(req,res)=>{
        const {email}=req.body;
        if(email){
            const user=await userModel.findOne({email:email});
            if(user){
                const secret=user._id + process.env.JWT_SECRET_KEY;   
                const token=jwt.sign({userID:user._id},secret,{expiresIn:'55m'})
                const link=`http://127.0.0.1:4000/api/user/reset/${user._id}/${token}`;
                console.log(link);
                
                //Send Email for Reset Password 
                //  let info=await transporter.sendMail({
                //     from:process.env.EMAIL_FROM,
                //     to:process.env.EMAIL_USER,
                //     subject:"GeekShop: Password Reset Link",
                //     html: `<a href=${link}>Click Here</a> to reset your password`,
                //  })

                let mailTransporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        user: 'xyz@gmail.com',
                        pass: 'xyz'
                    }
                });
                 
                let mailDetails = {
                    from: 'xyz@gmail.com',
                    to: 'xyz@gmail.com',
                    subject: 'xyz: Password Reset Link',
                    html: `<a href=${link}>Click Here</a> to reset your password`,

                };
                 
                mailTransporter.sendMail(mailDetails, function(err, data) {
                    if(err) {
                        console.log('Error Occurs');
                    } else {
                        console.log('Email sent successfully');
                    }
                });

                res.send({"status":"success","messege":"Password Reset Email sent.... Please check your mail","mailDetails":mailDetails});
            }else{
                res.send({"status":"failed","messege":"Email does not exist"});
            }

        }else{
            res.send({"status":"failed","messege":"Email is Required!!"});
        }
    }

    static userPasswordReset=async(req,res)=>{
        const {password,password_confirmation}=req.body;
        const {id,token}=req.params;
        const user=await userModel.findById(id);
        const new_secret=user._id + process.env.JWT_SECRET_KEY;
        try {
            jwt.verify(token,new_secret);
            if(password && password_confirmation){
                if(password !== password_confirmation){
                    res.send({"status":"failed","messege":"Password and Password Confirmation doesn't match"});

                }else{
                    const salt=await bcrypt.genSalt(10);
                    const newHashPassword=await bcrypt.hash(password,salt);
                    await userModel.findByIdAndUpdate(user._id, {$set: {password:newHashPassword}});
                    res.send({"status":"success","messege":"Password Reset Successfully"});

                }
            }else{
                res.send({"status":"failed","messege":"All fields are required"});
            }
        } catch (error) {
            console.log(error);
            res.send({"status":"failed","messege":"Invalid Token"});

        }
    }
    
}


export default userController;
