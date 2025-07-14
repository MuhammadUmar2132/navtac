const express = require('express');
const authController = require("../controller/authController")
const router = express.Router();
const auth = require('../middlewares/auth');


//-----------user-----------
router.get('/', (req, res)=>{
    res.json({msg:'Hello World123'})
});
//register
router.post('/register', authController.register),
//login
router.post('/login', authController.login);
// logout
router.post('/logout', auth, authController.logout);

// refresh
router.get('/refresh', authController.refresh);
//-----------blog-----------


// get all


// get blog by id


// update


// delete

// comment
// create 


// get 

//module export
module.exports = router;