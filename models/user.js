var mongoose = require('mongoose');
var bcrypt = require('bcrypt');

var UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    trim: true,   // remove any whitespaces before or after the text in case of accident
    unique: true,
  },
  name: {
    type: String,
    required: true,
    trim: true,
  },
  favoriteBook: {
    type: String,
    required: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  }
});

// authenticate input against database documents
// 'statics' object lets add methods directly to the model, so we can call them when we require the model in other files
UserSchema.statics.authenticate = function(email, password, callback) {
  User.findOne({ email: email })    // find document using the email address
      .exec(function (error, user) {
        // if error with the request
        if (error) {    
          return callback(error);
        } else if ( !user ) {
          // if email does not exist in any document
          var err = new Error('User not found.');
          err.status = 401;
          return callback(err);
        }
        // so user exists in the database, compare supplied password with the hashed version, results boolean
        bcrypt.compare(password, user.password, function(error, result) {
          if (result === true) {
            return callback(null, user);  // return null error and user document
          } else {
            return callback();
          }
        })
      });
}

// hash password before saving to database
UserSchema.pre('save', function(next) {
  var user = this;  // 'this' refers to data which will be written to Mongo, here user informations object from sign up
  bcrypt.hash(user.password, 10, function(err, hash) {
  // 1: user plain text password, 2: how many times to apply the encryption, 3: function run after hash is generated
    if (err) {
      return next(err);
    }
    user.password = hash;   // overwrite user plain text password with new secure hash
    next();     // call next middleware function, which is Mongo saving data
  })
});

var User = mongoose.model('User', UserSchema);
module.exports = User;