const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const User = require('../../model/User');
const OTPDetails = require('../../model/OtpDetails');
const key = require('../../config/keys').secret;

var request = require("request");

/**
 * @route POST api/users/register
 * @desc register the user
 * @access public
 */

 router.post('/register',(req,res)=>{
     let {
        name,
        email,
        phone,
        password,
        confirm_password,
        verified,
     } = req.body

     if(password !== confirm_password){
            // err.email = "Password Mismatch";
            // res.status(404).json({ err });
            // stop further execution in this callback
            return res.status(404).json({
                success:false,
                msg:"Password Mismatch."
            })
        }
        // User.findOne({ email: email }).exec().then(function (User){
            User.findOne({
                phone: req.body.phone
                }).then(user => {
            if (user&&!user.verified) {
              console.log(user)
            //   throw new Error("User profile already found") //reject promise with error
                return res.status(404).json({
                    success:false,
                    resp:"User profile already found",
                    msg: user
                })
             }
             else if(user&&!user.verified) {
                console.log(user)
              //   throw new Error("User profile already found") //reject promise with error
                  return res.status(404).json({
                      success:false,
                      msg: user
                  })
               }
             else { 
                const currentdate = Date.now()
                let newUser = new User({
                    name,
                    phone,
                    password,
                    email,
                    
                   //  date = currentdate
                });
                newUser.date = Date.now()     
                newUser.verified = "false";     
                bcrypt.genSalt(10,(err,salt) =>{
                    bcrypt.hash(newUser.password,salt,(err,hash)=>{
                        if(err) throw err;
                        newUser.password = hash;
                        newUser.save().then(user => {
                            return res.status(200).json({
                                success:true,
                                msg:"User Registered."
                            })
                        })
                    })
                })
               }
            
            
        }).catch(function (err){
            console.log(err); //User profile not found
            return res.status(404).json({ err }) //return your error msg
        })
 });
 
/**
 * @route POST api/users/sample
 * @desc resetpwd 
 * @access public
 */
router.get('/sample',(req,res)=>{
    return res.status(200).json({
        success:true,
        msg:"Sample reqest succeed."
    })
});



router.post('/resetpwd',(req,res) => {
    User.findOne({
        phone: req.body.phone
        }).then(user => {
            console.log(user);
                if(!user)
                    return res.status(404).json({
                        msg:"user not found",
                        success: false
                    })
                else 
                bcrypt.genSalt(10,(err,salt) =>{
                   bcrypt.hash(req.body.password,salt,(err,hash)=>{
                      if(err) throw err;
                           const newpassword = hash;

                    User.findOneAndUpdate({_id: user._id}, {password:newpassword},
                        {new: true, useFindAndModify: false}).then(response => {
                        if(response)
                          return res.status(200).json({
                            msg:"pwd updated",
                            success: true
                         }) 
                         else
                          return res.status(404).json({
                            msg:"Failed to update password",
                            success: false
                         }) 

                        })
                    })
                })
           })
    })


 /**
 * @route POST api/users/updateprofile
 * @desc update the profile i.e., email phone update
 * @access public
 */



router.post('/updateProfile',(req,res) => {
    User.findOne({
        email: req.body.email
        }).then(user => {
            console.log(user);
                if(!user)
                    return res.status(404).json({
                        msg:"user not found",
                        success: false
                    })
                else 
                    User.findOneAndUpdate({_id: user._id}, {email:req.body.email,phone:req.body.phone},
                        {new: true, useFindAndModify: false}).then(response => {
                        if(response)
                          return res.status(200).json({
                            msg:"profile updated",
                            success: true
                         }) 
                         else
                          return res.status(404).json({
                            msg:"Failed to update profile",
                            success: false
                         }) 

                        })
           })
    })





 /**
 * @route POST api/users/login
 * @desc login the user
 * @access public
 */

 router.post('/login',(req,res) => {
        User.findOne({
            email: req.body.email
            }).then(user => {
            if(!user){
                return res.status(404).json({
                    msg: "User Name Not Found",
                    success: false
                })
            }

        // check pwd if user exist.
        bcrypt.compare(req.body.password,user.password).then(isMatch => {
            if(isMatch) {
                    //  user auth valid, send jwt token to user
                    const payload = {
                        _id: user.id,
                        name: user.name,
                        email: user.email
                    }
                jwt.sign(payload,key,{
                    expiresIn:604800
                }, (err, token) => {
                     res.status(200).json({
                         success:true,
                         token:'Bearer '+token,
                         msg: "Login Successful."
                     })
                   }
                )
            }
            else {
                return res.status(404).json({
                    msg: "Invalid Credential",
                    success: false
                })
            }
        })
        })
 })

module.exports = router;
