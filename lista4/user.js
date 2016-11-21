var express = require("express");
var cookieParser = require('cookie-parser')
var Mustache = require("mustache");
var sha256 = require("sha256");

module.exports = function(db) {
  var user = express();
  user.use(cookieParser());

  user.get("/", function(req, res) {
    var sessionId = req.cookies.sessionId;
    db.get("SELECT name FROM users WHERE sessionId=$sessionId", {$sessionId: sessionId}, function(err, row) {
      if(row == undefined) {console.log("user not logged"); res.redirect("/login"); return;}
      res.send("user");
    });
  });

  return user;
}
