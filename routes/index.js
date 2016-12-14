var express = require('express');
var bCrypt = require('bcrypt-nodejs');
var User = require('../models/user');
var router = express.Router();

var isAuthenticated = function (req, res, next) {
	// if user is authenticated in the session, call the next() to call the next request handler 
	// Passport adds this method to request object. A middleware is allowed to add properties to
	// request and response objects
	if (req.isAuthenticated())
		return next();
	// if the user is not authenticated then redirect him to the login page
	res.redirect('/');
}

module.exports = function(passport){

	//GET login page
	router.get('/',function (req,res) {
		res.render('index');
	});

	//handle login POST
	router.post('/login', passport.authenticate('login', { 
		successRedirect: '/user',
	    failureRedirect: '/' 
	}));


	//handle GOOGLE sign in
	router.get('/auth/google', passport.authenticate('google', { scope : ['profile', 'email'] }));

	// the callback after google has authenticated the user
    router.get('/auth/google/callback', passport.authenticate('google', {
        successRedirect : '/user',
        failureRedirect : '/'
    }));

	//GET registration Page
	router.get('/signup',function (req,res) {
		res.render('signup');
	});

	//handle registration POST
	router.post('/signup',passport.authenticate('signup', { 
		successRedirect: '/',
	    failureRedirect: '/signup' 
	}));

	//GET user home page
	router.get('/user', isAuthenticated, function (req,res) {
		res.render('user',{user:req.user});
	});

	//GET delete user page
	router.get('/delete_user', isAuthenticated, function (req,res) {
		res.render('delete',{user:req.user});
	});

	//Handle delete user POST
	router.post('/delete_user',function (req,res) {
		User.remove({username:req.user.username},function (err, result) {
            if (err) return console.log(err)
                res.end(JSON.stringify(result))
            })
		req.logout();
		res.redirect('/');
	});

	//GET update user info page
	router.get('/update_user',isAuthenticated, function (req,res) {
		res.render('update',{user:req.user});
	});

	//Handle update user POST
	router.post('/update_user', function(req, res){
		console.log('req.body');
		console.log(req.body);

		if (req.body.phone == ''){
			req.body.phone = req.user.phone;
		}

		if (req.body.username == ''){
			req.body.username = req.user.username;
		}
		
		User.update({'email':req.user.email},
		{
			$set:{
				username: req.body.username,
				phone: req.body.phone
			}
		},function (err, result) {
			if (err) return console.log(err)
			console.log(JSON.stringify(result));
			res.end(JSON.stringify(result))
		})
		res.redirect('/user')
	})

	//GET to list all users
	router.get('/manage', function(req, res){
		User.find().exec(function(err, result){
			if(err) return console.log(err)
			res.render('manage',{users:result})
		})
	})
	
	//GET to sign a user out
	router.get('/signout', function(req, res) {
			req.logout();
			res.redirect('/');
	});

	return router;
}
