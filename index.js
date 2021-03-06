var express = require('express');
var app     = express();

var morgan       = require('morgan');
var http         = require('http');
var path         = require('path');
var passport     = require('passport'),
    LocalStrategy = require('passport-local').Strategy;
var mongoose     = require('mongoose');
var flash        = require('express-flash');
var cookieParser = require('cookie-parser');
var bodyParser   = require('body-parser');
var session      = require('express-session');
var bcrypt       = require('bcrypt-nodejs');
var async        = require('async');
var crypto       = require('crypto');
var nodemailer   = require('nodemailer');

var config       = require('./config.js');

var port         = process.env.PORT || config.port || 8080;

var mongoConnString = 'mongodb://' + config.mongo.url + '/' + config.mongo.database;

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

// passport.js configuration
passport.use(new LocalStrategy(function(username, password, done) {
    console.log('Hi from passport.use. ' + username + ' ' + password + ' ' + done);
    User.findOne({username: username, activated: true }, function(err, user) {
	if (err) {
	    return done(err);
	}
	if (!user) return done(null, false, { message: 'Incorrect username.' });
	user.comparePassword(password, function(err, isMatch) {
	    if (isMatch) {
		return done(null, user);
	    } else {
		return done(null, false, { message: 'Incorrect password.' });
	    }
	});
    });
}));

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
	done(err, user);
    });
});

var userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email:    { type: String, required: true, unique: true },
    password: { type: String, required: true },
    activated: { type: Boolean, required: true, default: false },
    activateAccountToken: String,
    activationDate: { type: Date, default: undefined },
    resetPasswordToken: String,
    resetPasswordExpires: Date
});

userSchema.pre('save', function(next) {
  var user = this;
  var SALT_FACTOR = 5;

  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
  console.log('comparePassowrd() called.');
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) return cb(err);
    return cb(null, isMatch);
  });
};

var User = mongoose.model('User', userSchema);
// passport.js configuration ends

mongoose.connect(mongoConnString);

app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(session({ secret: config.sessionSecret }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));
app.use(flash());

app.get('/', function(req, res, next) {
    res.render('layout', {
	user: req.user,
	title: config.title
    });
} );

app.get('/login', function(req, res) {
    res.render('login', {
	user: req.user,
	title: config.title
    });
});

app.post('/login', function(req, res, next) {
    passport.authenticate('local', function(err, user, info) {
	if (err) return next(err)
	if (!user) {
	    req.flash('error', 'Username not found.');
	    return res.redirect('/login')
	}
	req.logIn(user, function(err) {
	    if (err) return next(err);
	    return res.redirect('/');
	});
    })(req, res, next);
});

app.get('/signup', function(req, res) {
    res.render('signup', {
	user: req.user,
	title: config.title
    });
});

    // app.post('/signup', function(req, res) {
    // 	var user = new User({
    // 	    title: config.title,
    // 	    username: req.body.username,
    // 	    email: req.body.email,
    // 	    password: req.body.password
    // 	});

    // 	user.save(function(err) {
    // 	    req.logIn(user, function(err) {
    // 		res.redirect('/');
    // 	    });
    // 	});
    // });

app.post('/signup', function(req, res, next) {
    async.waterfall([
	// create a new User
	function(done) {
	    crypto.randomBytes(20, function(err, buf) {
		var token = buf.toString('hex');
		console.log('activationToken ' + token + ' created for ' + req.body.email)
		done(err, token);
	    });
	},

    	function(token, done) {

	    User.findOne({ email: req.body.email }, function(err, user) {
		if (err) {
		    console.log(err);
		}

		if (user) {
		    console.log(req.body.email + ' record already exists in database.')
		    req.flash('error', 'Entered email already taken.');
		    return res.redirect('/signup');
		}

		var user = new User({
    		    username: req.body.username,
    		    email: req.body.email,
    		    password: req.body.password,
		    activated: false,
		    activateAccountToken: token,
    		});
		done(err, token, user);
	    });

	},

	function(token, user, done) {
	    user.save(function(err) {
		console.log('New account ' + user.email + ' saved.')
		done(err, token, user);
	    });
	},

	function(token, user, done) {
	    var smtpTransport = nodemailer.createTransport('SMTP', {
		service: config.email.service,
		auth: {
		    user: config.email.senderAccount,
		    pass: config.email.senderPassword,
		}
	    });
	    var mailOptions = {
		to: user.email,
		from: config.email.senderAccount,
		subject: config.title + ': Your Account Being Set Up',
		text: 'You are receiving this because you (or someone else) have requested to sign up a new account for email ' + user.email + '.\n\n' +
		    'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
		    'http://' + req.headers.host + '/activate/' + token + '\n\n' +
		    'If you did not request this, please ignore this email and your password will remain unchanged.\n'
	    };
	    smtpTransport.sendMail(mailOptions, function(err) {
		req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
		done(err, 'done');
	    });
	},
    ], function(err) {
	if (err) return next(err);
	res.redirect('/signup');
    });
});  // end post /signup

app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/');
});

app.get('/forgot', function(req, res) {
    res.render('forgot', {
	user: req.user,
	title: config.title
    });
});

app.post('/forgot', function(req, res, next) {
    async.waterfall([
	function(done) {
	    crypto.randomBytes(20, function(err, buf) {
		var token = buf.toString('hex');
		done(err, token);
	    });
	},
	function(token, done) {
	    User.findOne({ email: req.body.email, activated: true }, function(err, user) {
		if (!user) {
		    req.flash('error', 'No account with that email address exists.');
		    return res.redirect('/forgot');
		}
		
		user.resetPasswordToken = token;
		user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

		user.save(function(err) {
		    done(err, token, user);
		});
	    });
	},
	function(token, user, done) {
	    var smtpTransport = nodemailer.createTransport('SMTP', {
		service: config.email.service,
		auth: {
		    user: config.email.senderAccount,
		    pass: config.email.senderPassword,
		}
	    });
	    var mailOptions = {
		to: user.email,
		from: config.email.senderAccount,
		subject: config.title + ': Password Forgot',
		text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
		    'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
		    'http://' + req.headers.host + '/reset/' + token + '\n\n' +
		    'If you did not request this, please ignore this email and your password will remain unchanged.\n'
	    };
	    smtpTransport.sendMail(mailOptions, function(err) {
		req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
		done(err, 'done');
	    });
	}
    ], function(err) {
	if (err) return next(err);
	res.redirect('/forgot');
    });
});

app.get('/activate/:token', function(req, res, next) {
    console.log('get /activate/ called with token: ' + req.params.token);
    User.findOne({ activateAccountToken: req.params.token, activated: false }, function(err, user) {
	if (!user) {
	    req.flash('error', 'Token you specified did not match any account.');
	    return res.redirect('/');
	}

	user.activated = true;
	user.activateAccountToken = undefined;
	user.activationDate = Date.now();

	user.save(function(err) {
	    if (err) next(err);
	    else {
		req.flash('success', 'Success! Your account is now activated.');

	    // passport.authenticate('local', function(err, user, info) {
	    // 	if (err) return next(err)
	    // 	if (!user) {
	    // 	    req.flash('error', 'Username not found.');
	    // 	}
	    // 	req.logIn(user, function(err) {
	    // 	    if (err) return next(err);
	    // 	    return res.redirect('/');
	    // 	});
	    // })(req, res, next);

		res.render('activate', {
	    	    title: config.title,
	    	    user: req.user
		});
	    }
	});
    });
});

app.get('/reset/:token', function(req, res) {
    User.findOne({ resetPasswordToken: req.params.token, activated: true, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
	if (!user) {
	    req.flash('error', 'Password reset token is invalid or has expired.');
	    return res.redirect('/forgot');
	}
	res.render('reset', {
	    title: config.title,
	    user: req.user
	});
    });
});

app.post('/reset/:token', function(req, res) {
    async.waterfall([
	function(done) {
	    User.findOne({ resetPasswordToken: req.params.token, activated: true, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
		if (!user) {
		    req.flash('error', 'Password reset token is invalid or has expired.');
		    return res.redirect('back');
		}

		user.password = req.body.password;
		user.resetPasswordToken = undefined;
		user.resetPasswordExpires = undefined;

		user.save(function(err) {
		    req.logIn(user, function(err) {
			done(err, user);
		    });
		});
	    });
	},
	function(user, done) {
            var smtpTransport = nodemailer.createTransport('SMTP', {
		service: config.email.service,
		auth: {
		    user: config.email.senderAccount,
		    pass: config.email.senderPassword,
		}
	    });
	    var mailOptions = {
		to: user.email,
		from: config.email.senderAccount,
		subject: config.title + ': Your Password Now Reset',
		text: 'Hello,\n\n' +
		    'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
	    };
	    smtpTransport.sendMail(mailOptions, function(err) {
		req.flash('success', 'Success! Your password has been changed.');
		done(err);
	    });
	}
    ], function(err) {
	res.redirect('/');
    });
});

app.listen(port, function() {
    console.log('app started on port ' + port);
} );
