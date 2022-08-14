import express from 'express';
const router=express.Router();
import userController from '../controllers/userController.js';
import checkUserAuth from '../middlewares/auth-middleware.js';

//Route Level middleware - To Protect Route
router.use('/changepassword',checkUserAuth);
router.use('/loggeduser',checkUserAuth);


//Public Routes
router.post('/register', userController.userRegistration);
router.post('/login',userController.userLogin);
router.post('/send-reset-password-email',userController.sendUserPasswordResetEmail);
router.post('/reset-passowrd/:id/:token',userController.userPasswordReset);



//Protected Routes
router.post('/changepassword',userController.changeUserPassword);
router.get('/loggeduser', userController.loggedUser);



export default router;